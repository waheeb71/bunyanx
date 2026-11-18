"""
Enterprise bunyanx — Data Loss Prevention (DLP) Inspector Plugin

Detection Layers:
  1. Regex-based content inspection  (SSN, CC, IBAN, custom rules)
  2. BEFP behavioral entropy analysis (5 signals → ERS)
  3. AI Isolation Forest fusion       (ERS + anomaly score → final decision)

Hybrid decision engine (per supervisor's recommendation):
  ERS ≥ 0.35  → Alert
  ERS ≥ 0.60  → Rate Limit (surfaced as HIGH finding)
  ERS ≥ 0.80  → Deception Trap (if deception_enabled) or Block
  ERS ≥ 0.95  → Immediate Block (regardless of deception setting)

Response Inspection (DLP Egress Guard):
  Server responses traversing the proxy are inspected by inspect_response()
  BEFORE the payload reaches the client. Any content match immediately
  terminates the relay and returns BLOCK, preventing data exfiltration via
  HTTP responses (e.g. GET /api/leak-cc → 200 OK with CC numbers in body).

  Called from transparent_proxy._relay_data() on the server→client path.
"""

import logging
from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionFinding,
    InspectionResult, InspectionAction
)
from modules.dlp.engine.dlp_engine import DLPEngine
from system.core.deception.unified_engine import UnifiedDeceptionEngine
from modules.dlp.engine.file_parser import FileParser

logger = logging.getLogger(__name__)


class DLPInspectorPlugin(InspectorPlugin):
    """
    Unified DLP Inspector Plugin.

    Operates in two modes:

    1. REQUEST mode (InspectionPipeline path):
       Called by InspectionBridge on every client→server request.
       Inspects HTTP request body, POST payloads, file uploads.

    2. RESPONSE mode (Relay path):
       Called directly from transparent_proxy._relay_data() on the
       server→client chunk BEFORE it is forwarded to the client.
       Inspects response body for sensitive data (CC, SSN, source code).
       Returns InspectionResult with action=BLOCK on any content match.
    """

    def __init__(self):
        super().__init__(name="dlp_inspector", priority=60)
        self.unified_deception = UnifiedDeceptionEngine()
        self.engine = DLPEngine()

    def can_inspect(self, context: InspectionContext) -> bool:
        return True

    # ── Mode 1: REQUEST inspection (pipeline path, client→server) ────────────

    def inspect(self, context: InspectionContext, data: bytes = b"") -> InspectionResult:
        findings = []
        action = InspectionAction.ALLOW

        # ── Phase 10: Typed field adapter ─────────────────────────────────────
        # When InspectionBridge calls check(ctx), data=b"". Body is in ctx.http.body.
        if not data and context.http is not None:
            data = context.http.body

        # Skip inbound traffic unless explicitly configured
        if context.direction == "inbound" and not context.metadata.get("inspect_inbound_dlp", False):
            return InspectionResult(action=action, findings=[])

        if not self.engine.is_active:
            return InspectionResult(action=action, findings=[])

        block_policy = self.engine.block_on_match
        
        # [REMEDIATION-TASK-2] Enforcement of Fail-Closed Policy
        # Defaults to True to ensure Zero Trust Execution Mode
        fail_closed = context.metadata.get("fail_closed", True)

        # ── Phase 10: Internal Network Check (typed) ────────────────────────
        # Use ConfigLoader.is_internal() instead of manual prefix string check.
        # This ensures consistency with ContextBuilder network tagging.
        from system.core.config_loader import ConfigLoader
        _src_ip = context.src_ip or ""
        _src_is_internal = context.is_internal or ConfigLoader.is_internal(_src_ip)

        try:
            # ── Layer 1 & 2: Text-based content inspection ─────────────────────
            # NOTE: We scan ALL sources including internal (192.168.x).
            # The 50-finding cap in dlp_engine.evaluate() prevents the 1700ms
            # performance issue without skipping the scan entirely.
            # Internal sources remain MONITOR-ONLY in the decision below (not blocked),
            # but DLP still DETECTS and logs CC/SSN patterns for analyst review.
            filename = (
                # Phase 10: check http headers first (Content-Disposition)
                (context.http.headers.get("content-disposition", "") if context.http else "")
                or context.metadata.get("filename", "")
            )
            text_data = FileParser.extract_text(data, filename)

            if text_data:
                content_findings = self.engine.evaluate(text_data)
                for f in content_findings:
                    findings.append(
                        InspectionFinding(
                            plugin_name=self.name,
                            severity=f["severity"],
                            category="DLP",
                            description=f["description"],
                            confidence=0.95,
                            recommends_block=block_policy,
                            metadata={
                                "rule_id": f.get("rule_id"),
                                "rule_name": f["rule_name"],
                                "match_count": f["match_count"],
                                "detection_layer": "content",
                            }
                        )
                    )


            # ── Layer 3: BEFP + AI Behavioral Analysis ──────────────────────────
            befp_result = None
            ai_result = None
            
            befp_result, ai_result, behavioral_findings = self.engine.evaluate_behavioral(
                raw_payload=data,
                src_ip=context.src_ip,
                dst_ip=context.dst_ip,
                protocol=context.protocol,
                dst_port=context.dst_port,
            )

            for f in behavioral_findings:
                decision = ai_result.decision if ai_result else "SUSPICIOUS"
                confidence = f.get("final_score", f.get("ers", 0.5))

                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity=f["severity"],
                        category="DLP_BEHAVIORAL",
                        description=f["description"],
                        confidence=round(confidence, 3),
                        recommends_block=decision in ("HIGH_RISK", "EXFILTRATION"),
                        metadata={
                            "rule_name": f["rule_name"],
                            "match_count": 1,
                            "detection_layer": "behavioral_befp",
                            "ers": befp_result.ers if befp_result else 0,
                            "ai_score": f.get("ai_score", 0),
                            "final_score": f.get("final_score", 0),
                            "model_available": f.get("model_available", False),
                            "signals": f.get("metadata", {}).get("signals", {}),
                        }
                    )
                )

            # ── Hybrid Decision Engine ──────────────────────────────────────────
            if not findings:
                return InspectionResult(action=action, findings=[])

            # Determine effective risk score
            final_score = 0.0
            if ai_result:
                final_score = ai_result.final_score
            elif befp_result:
                final_score = befp_result.ers
            elif findings:
                final_score = 0.85  # Content match defaults to high confidence

            # Supervisor's recommended tiered decision:
            if final_score >= 0.95:
                # Immediate Block — no deception, this is definitive
                action = InspectionAction.BLOCK
                logger.critical(
                    f"[DLP BLOCK] Definitive exfiltration blocked | "
                    f"IP={context.src_ip} score={final_score:.3f}"
                )

            elif final_score >= self.engine.befp_block_threshold and self.engine.deception_enabled:
                # Deception Trap — mislead the attacker with synthetic response
                try:
                    trap_id, watermark_payload = self.unified_deception.generate_trap(
                        module="dlp",
                        username=context.metadata.get("username", "unknown"),
                        source_ip=context.src_ip,
                        target_service="egress_dlp",
                        anomaly_score=final_score,
                    )
                    action = InspectionAction.REDIRECT_DECOY
                    context.metadata = context.metadata or {}
                    context.metadata["deception_trap"]   = watermark_payload
                    context.metadata["befp_final_score"] = final_score
                    logger.warning(
                        f"[DLP DECEIVE] Watermark trap injected | "
                        f"IP={context.src_ip} score={final_score:.3f} trap={trap_id}"
                    )
                except Exception as e:
                    logger.error(f"Deception trap generation failed: {e}")
                    action = InspectionAction.BLOCK

            elif final_score >= self.engine.befp_block_threshold or (block_policy and _has_content_findings(findings)):
                # ── Internal-User Exception (Zero-Trust with Trust Level) ──────
                # For legitimate internal users performing authorized transactions
                # (e.g. bank employees submitting credit card data to the bank app),
                # downgrade BLOCK → ALERT to avoid disrupting business operations.
                #
                # Rule: Content match from internal IP + low behavioral score
                #       (final_score < befp_block_threshold) → ALERT only.
                #       External IPs or high behavioral risk → always BLOCK.
                if (
                    _src_is_internal
                    and final_score < self.engine.befp_block_threshold
                    and not _has_content_findings(findings)
                    and not any(
                        f.category == "DLP_BEHAVIORAL" and f.metadata.get("final_score", 0) >= 0.60
                        for f in findings
                    )
                ):
                    action = InspectionAction.LOG_ONLY
                    logger.info(
                        "[DLP ALERT] Internal user non-critical content match — downgraded to LOG_ONLY (monitor) | "
                        "IP=%s score=%.3f [block_policy=%s, internal=True]",
                        context.src_ip, final_score, block_policy
                    )
                else:
                    # Block — external source, high behavioral risk, or critical content match
                    action = InspectionAction.BLOCK
                    logger.warning(
                        "[DLP BLOCK] High-risk traffic blocked | "
                        "IP=%s score=%.3f internal=%s",
                        context.src_ip, final_score, _src_is_internal,
                    )

            # ── Log final decision & publish EventBus audio alert ──────────────
            if findings:
                try:
                    import time
                    import uuid
                    from system.events.bus import EventBus
                    from system.events.topics import Topics
                    pattern_types = list({f.metadata.get("rule_name", f.category) for f in findings if f.metadata})
                    first_rule = (pattern_types[0] if pattern_types else "").lower()
                    threat_type = "dlp"
                    if "credit" in first_rule or "card" in first_rule or "pci" in first_rule:
                        threat_type = "credit_card"
                    elif "iban" in first_rule or "bank" in first_rule:
                        threat_type = "iban"
                    elif "ssn" in first_rule or "social" in first_rule:
                        threat_type = "ssn"
                    elif "passport" in first_rule:
                        threat_type = "passport"
                    elif "email" in first_rule:
                        threat_type = "email"

                    payload = {
                        "event_id": str(uuid.uuid4()),
                        "timestamp_utc": time.time(),
                        "module": "dlp",
                        "direction": "REQUEST",
                        "src_ip": context.src_ip,
                        "dst_ip": context.dst_ip,
                        "src_port": context.src_port or 0,
                        "dst_port": context.dst_port or 0,
                        "protocol": context.protocol or "HTTP",
                        "decision": "CONTENT_MATCH" if _has_content_findings(findings) else "BEHAVIORAL",
                        "action_taken": action.name,
                        "action": action.name,
                        "severity": findings[0].severity if findings else "MEDIUM",
                        "threat_type": threat_type,
                        "category": threat_type,
                        "ers": befp_result.ers if befp_result else 0.0,
                        "ai_score": ai_result.ai_anomaly_score if ai_result else 0.0,
                        "final_score": final_score,
                        "match_count": len(findings),
                        "pattern_types": pattern_types,
                        "description": findings[0].description if findings else "DLP Request Scan",
                    }
                    EventBus.publish_from_thread(Topics.DLP_INCIDENT, payload)
                except Exception as exc:
                    logger.debug("Failed to dispatch DLP event to EventBus: %s", exc)

            if action == InspectionAction.BLOCK:
                logger.warning(
                    "[DLP BLOCK] Data exfiltration blocked | IP=%s score=%.3f",
                    context.src_ip,
                    final_score,
                )

            return InspectionResult(action=action, findings=findings)

        except Exception as e:
            logger.critical(f"[DLP FATAL] Unexpected failure during inspection: {e}. Applying fail-closed policy.")
            if fail_closed:
                error_finding = InspectionFinding(
                    plugin_name=self.name,
                    severity="CRITICAL",
                    category="DLP_SYSTEM_FAILURE",
                    description=f"DLP Engine Exception: {str(e)} (Fail-Closed triggered)",
                    confidence=1.0,
                    recommends_block=True,
                )
                return InspectionResult(action=InspectionAction.BLOCK, findings=[error_finding])
            else:
                return InspectionResult(action=InspectionAction.ALLOW, findings=[])

    # ── Mode 2: RESPONSE inspection (relay path, server→client) ─────────────

    def inspect_response(
        self,
        raw_chunk: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "HTTP",
        url: str = "",
        response_headers: dict = None,
    ) -> InspectionResult:
        """
        Inspect a server→client response chunk for sensitive data exfiltration.

        Called from transparent_proxy._relay_data() BEFORE the chunk is
        forwarded to the client. Any confirmed content match returns BLOCK
        immediately — the relay then terminates the connection and sends a
        549 DLP Block response to the client.

        Design decisions:
          - Does NOT run BEFP/AI behavioral analysis (behavioral signals are
            meaningful for REQUEST patterns, not short response chunks).
          - Applies HTTP response header stripping first to avoid false
            positives on innocuous response metadata.
          - Hard cap: raw_chunk larger than DLP_MAX_RESPONSE_SCAN_BYTES is
            only partially scanned (first + last N bytes) to protect latency.
          - Fail-OPEN on engine errors to avoid blocking legitimate traffic
            due to DLP subsystem failures (opposite of request path which
            is fail-closed by default, since requests are attacker-controlled).

        Args:
            raw_chunk:        Raw bytes of the server response (may be partial).
            src_ip:           Client IP (the recipient of this response).
            dst_ip:           Internal server IP (the source of the response).
            src_port:         Client port.
            dst_port:         Server port.
            protocol:         "HTTP" or "HTTPS".
            url:              Original request URL (for logging context).
            response_headers: Parsed response headers dict (optional).

        Returns:
            InspectionResult with:
              - action=ALLOW  → forward the chunk normally
              - action=BLOCK  → terminate relay, send DLP block response
        """
        if not raw_chunk:
            return InspectionResult(action=InspectionAction.ALLOW, findings=[])

        if not self.engine.is_active:
            return InspectionResult(action=InspectionAction.ALLOW, findings=[])

        try:
            # ── Strip HTTP response envelope if present ────────────────────────
            # A raw chunk might start with "HTTP/1.1 200 OK\r\n..." — we strip
            # the response status line + headers so the regex scanner only sees
            # the actual body payload. This prevents false positives on header
            # fields like "Server: Apache/2.4.51" matching custom rules.
            scan_bytes = _strip_http_response_envelope(raw_chunk)

            # ── Size guard: scan first 512 KB + last 16 KB of large chunks ─────
            DLP_MAX_SCAN_BYTES = 512 * 1024   # 512 KB
            DLP_TAIL_BYTES     = 16 * 1024    # 16 KB tail
            if len(scan_bytes) > DLP_MAX_SCAN_BYTES:
                scan_bytes = (
                    scan_bytes[:DLP_MAX_SCAN_BYTES]
                    + scan_bytes[-DLP_TAIL_BYTES:]
                )
                logger.debug(
                    "[DLP-RSP] Large chunk truncated for scanning "
                    "(src=%s url=%s)", src_ip, url
                )

            # ── Extract text (handles gzip, base64, JSON, plain text) ──────────
            content_type = (response_headers or {}).get("content-type", "")
            text_data = FileParser.extract_text(scan_bytes, filename=content_type)

            if not text_data:
                return InspectionResult(action=InspectionAction.ALLOW, findings=[])

            # ── Layer 1 & 2: regex content scan ──────────────────────────────
            content_findings = self.engine.evaluate(
                text_data,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
            )

            if not content_findings:
                return InspectionResult(action=InspectionAction.ALLOW, findings=[])

            # ── Build InspectionFinding objects ────────────────────────────────
            findings = []
            for f in content_findings:
                findings.append(
                    InspectionFinding(
                        plugin_name=self.name,
                        severity=f["severity"],
                        category="DLP_RESPONSE",
                        description=(
                            f"[EGRESS] {f['description']} "
                            f"(url={url or dst_ip})"
                        ),
                        confidence=0.97,
                        recommends_block=True,
                        metadata={
                            "rule_id": f.get("rule_id"),
                            "rule_name": f["rule_name"],
                            "match_count": f["match_count"],
                            "detection_layer": "response_content",
                            "url": url,
                            "src_ip": src_ip,
                        },
                    )
                )

            # ── Decision: Check recipient client IP, URL path & block_on_match ─
            from system.core.config_loader import ConfigLoader
            _recipient_is_internal = ConfigLoader.is_internal(src_ip)
            block_policy = self.engine.block_on_match

            # Check if this is an internal Web UI / Dashboard page:
            _url_lower = (url or "").lower()
            _is_ui_path = any(
                p in _url_lower
                for p in ("/dashboard", "/web-ui", "/assets/", "/static/", "/favicon", "/api/v1/system", "/api/v1/status")
            )
            _is_html_page = "text/html" in content_type.lower()

            if not block_policy:
                action = InspectionAction.LOG_ONLY
                logger.info(
                    "[DLP-RSP] ⚠️ ALERT egress match (monitor mode) | src=%s url=%s patterns=%s",
                    src_ip, url or dst_ip, list({f["rule_name"] for f in content_findings})[:5]
                )
            elif _recipient_is_internal and (_is_ui_path or _is_html_page):
                # Internal admin browsing web UI / dashboard page -> Alert only to avoid blocking system UI
                action = InspectionAction.LOG_ONLY
                logger.info(
                    "[DLP-RSP] ⚠️ ALERT egress match for internal web UI dashboard (allowed) | src=%s url=%s patterns=%s",
                    src_ip, url or dst_ip, list({f["rule_name"] for f in content_findings})[:5]
                )
            else:
                # Enforcement mode -> BLOCK egress exfiltration (file downloads, API leaks, external exfiltration)
                action = InspectionAction.BLOCK
                logger.warning(
                    "[DLP-RSP] 🚫 BLOCK egress exfiltration | src=%s url=%s patterns=%s findings=%d",
                    src_ip, url or dst_ip, list({f["rule_name"] for f in content_findings})[:5], len(findings)
                )

            # ── EventBus notification (audio + SSE) ────────────────────────────
            try:
                import time
                import uuid
                from system.events.bus import EventBus
                from system.events.topics import Topics
                pattern_types = list({f["rule_name"] for f in content_findings})
                EventBus.publish_from_thread(
                    Topics.DLP_INCIDENT,
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp_utc": time.time(),
                        "module": "dlp",
                        "direction": "RESPONSE",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "decision": "CONTENT_MATCH",
                        "action_taken": action.name,
                        "action": action.name,
                        "severity": findings[0].severity if findings else "HIGH",
                        "ers": 0.0,
                        "ai_score": 0.0,
                        "final_score": 0.85,
                        "match_count": len(findings),
                        "pattern_types": pattern_types,
                        "description": findings[0].description if findings else "DLP Response Egress Scan",
                    },
                )
            except Exception as _pub_exc:
                logger.debug("[DLP-RSP] EventBus publish failed: %s", _pub_exc)

            return InspectionResult(action=action, findings=findings)

        except Exception as exc:
            # Fail-OPEN on response path: DLP engine error should not
            # block legitimate server responses. Log at ERROR for monitoring.
            logger.error(
                "[DLP-RSP] Engine error during response inspection (fail-open): "
                "%s | src=%s url=%s", exc, src_ip, url
            )
            return InspectionResult(action=InspectionAction.ALLOW, findings=[])


# ── Module-level helpers ──────────────────────────────────────────────────────

def _has_content_findings(findings) -> bool:
    """Check if any finding came from the content inspection layer and warrants a block."""
    _HIGH_SEVERITY_TYPES = {
        "SSN", "PASSPORT", "IBAN", "TAX_ID", "NATIONAL_ID",
        "PRIVATE_KEY", "AWS_KEY", "API_KEY", "CREDIT_CARD",
    }
    
    non_critical_count = 0
    for f in findings:
        if not f.metadata or f.metadata.get("detection_layer") not in ("content", "response_content"):
            continue
        
        rule_name = f.metadata.get("rule_name", "")
        if rule_name.startswith("BUILTIN_"):
            pattern_type = rule_name.replace("BUILTIN_", "")
            if pattern_type in _HIGH_SEVERITY_TYPES:
                return True
            else:
                non_critical_count += f.metadata.get("match_count", 1)
        else:
            # Custom rules are defined by admin, so block if block_on_match is enabled
            return True
            
    # Block on non-critical patterns only if there are multiple matches (bulk leak threshold e.g. >= 3)
    if non_critical_count >= 3:
        return True
        
    return False


def _strip_http_response_envelope(raw: bytes) -> bytes:
    """
    Strip the HTTP response status line + headers from raw bytes, returning
    only the body. Handles both \\r\\n\\r\\n and \\n\\n delimiters.

    If no valid HTTP response header is found (e.g. chunk is a continuation),
    the raw bytes are returned as-is so the scanner can still inspect them.

    Examples:
      b"HTTP/1.1 200 OK\\r\\n...\\r\\n\\r\\n<body>" → b"<body>"
      b"<raw-body-chunk>"                           → b"<raw-body-chunk>"
    """
    if not raw:
        return raw

    # Must start with "HTTP/" to be a response envelope
    if not raw[:5].upper().startswith(b"HTTP/"):
        return raw

    # Find header/body separator
    sep = raw.find(b"\r\n\r\n")
    if sep != -1:
        return raw[sep + 4:]

    sep = raw.find(b"\n\n")
    if sep != -1:
        return raw[sep + 2:]

    # No separator found — still scanning headers, return empty (no body yet)
    return b""
