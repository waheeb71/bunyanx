"""
Enterprise bunyanx — AI-Powered Email Security Inspector

Replaces and evolves the legacy `smtp_inspector.py` by routing all
email protocol traffic through a multi-layer AI security pipeline.

Protocol coverage:
  - SMTP  (port 25, 587, 465) — inbound + outbound mail
  - IMAP  (port 143, 993)     — mail retrieval
  - POP3  (port 110, 995)     — mail retrieval

7-Layer AI Detection Pipeline:
  ─────────────────────────────────────────────────────
  0. Settings / Whitelist Gate       (master on/off + trusted senders)
  1. Email Preprocessor              (MIME decode + URL + attachment extract)
  2. Phishing Detector               (keyword + urgency + brand spoof + NLP)
  3. URL Scanner                     (shorteners + TLD + IP-literal + reputation)
  4. Attachment Guard                (extension + entropy + MIME mismatch)
  5. Sender Reputation               (SPF + DKIM + DMARC + disposable domain + IP)
  6. Spam Filter                     (keyword + caps + hidden text)
  7. Risk Scoring Engine             (weighted sum → ALLOW / QUARANTINE / BLOCK)
  ─────────────────────────────────────────────────────

Integration with existing framework:
  - InspectorPlugin base class
  - InspectionContext, InspectionResult, InspectionFinding
  - core/threat_intel.py  (IP + domain reputation)
  - Replaces: smtp_inspector.py (kept in place as legacy fallback)

Settings:
  config/defaults/email.yaml    — per-feature enable/disable + weights
  config/email.local.yaml       — API keys and local overrides
"""

import logging
import re
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, TYPE_CHECKING

from system.events.bus import EventBus
from system.events.topics import Topics
from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionFinding,
    InspectionResult, InspectionAction, PluginPriority,
)
from modules.email_security.engine.core.settings          import EmailSettings, get_email_settings
from modules.email_security.engine.utils.preprocessor      import EmailPreprocessor
from modules.email_security.engine.scanners.phishing_detector import PhishingDetector
from modules.email_security.engine.scanners.url_scanner       import URLScanner
from modules.email_security.engine.scanners.attachment_guard  import AttachmentGuard
from modules.email_security.engine.scanners.sender_reputation import SenderReputation
from modules.email_security.engine.scanners.spam_filter       import SpamFilter
from modules.email_security.engine.core.risk_engine       import EmailRiskEngine, EmailPolicyDecision

# ── AI engines: PLSF + VSDE ───────────────────────────────────────────
try:
    from modules.email_security.engine.scanners.psycho_linguistic_profiler import PsychoLinguisticProfiler
    _PLSF_AVAILABLE = True
except ImportError:
    _PLSF_AVAILABLE = False

try:
    from modules.email_security.engine.scanners.visual_desync_scanner import VisualDesyncScanner
    _VSDE_AVAILABLE = True
except ImportError:
    _VSDE_AVAILABLE = False

if TYPE_CHECKING:
    from modules.ids_ips.engine.anomaly_detector import AnomalyDetector
    # pyrefly: ignore [missing-import]
    from system.core.threat_intel import ThreatIntelCache

logger = logging.getLogger(__name__)

# Module-level compiled regex
_DOMAIN_RE = re.compile(r'@([\w.\-]+)')

# SMTP command patterns that indicate reconnaissance
_DANGEROUS_SMTP_COMMANDS = {"VRFY", "EXPN", "DEBUG"}


class EmailInspectorPlugin(InspectorPlugin):
    """
    AI-Powered Email Security Inspector.

    Automatically activated when traffic arrives on email ports
    (25, 587, 465, 143, 993, 110, 995). Routes packets through a
    7-layer detection pipeline driven by `config/defaults/email.yaml`.

    Args:
        settings:     EmailSettings (loaded from YAML if None)
        threat_intel: Optional ThreatIntelCache for IP + domain reputation
        priority:     Plugin execution priority
    """

    def __init__(
        self,
        settings:     Optional[EmailSettings] = None,
        threat_intel: Optional['ThreatIntelCache'] = None,
        priority:     PluginPriority = PluginPriority.HIGH,
    ):
        super().__init__(name="email_ai_inspector", priority=priority)

        # ── Load settings ─────────────────────────
        self.cfg = settings or get_email_settings()
        self.threat_intel = threat_intel
        self._db_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="email_db")

        # ── Build sub-components from settings ────
        pp_cfg = self.cfg.preprocessing
        self.preprocessor = EmailPreprocessor(
            decode_base64       = pp_cfg.decode_base64_body,
            decode_qp           = pp_cfg.decode_quoted_printable,
            extract_plain_text  = pp_cfg.extract_plain_text,
            max_body_bytes      = pp_cfg.max_body_bytes,
        )

        ph_cfg = self.cfg.phishing
        self.phishing_detector = PhishingDetector(
            settings = ph_cfg,
        )

        us_cfg = self.cfg.url_scanner
        self.url_scanner = URLScanner(
            settings     = us_cfg,
            threat_intel = self.threat_intel,
        )

        ag_cfg = self.cfg.attachment_guard
        self.attachment_guard = AttachmentGuard(
            settings = ag_cfg,
        )

        sr_cfg = self.cfg.sender_reputation
        self.sender_reputation = SenderReputation(
            settings     = sr_cfg,
            threat_intel = self.threat_intel,
        )

        sf_cfg = self.cfg.spam_filter
        self.spam_filter = SpamFilter(
            settings = sf_cfg,
        )

        thr = self.cfg.thresholds
        self.risk_engine = EmailRiskEngine(
            w_phishing   = ph_cfg.weight,
            w_url        = us_cfg.weight,
            w_attachment = ag_cfg.weight,
            w_sender     = sr_cfg.weight,
            w_spam       = sf_cfg.weight,
            w_plsf       = self.cfg.plsf.weight  if getattr(self.cfg, 'plsf', None) else 0.10,
            w_vsde       = self.cfg.vsde.weight  if getattr(self.cfg, 'vsde', None) else 0.05,
            threshold_allow      = thr.allow,
            threshold_quarantine = thr.quarantine,
            threshold_block      = thr.block,
            thresholds           = thr,   # pass full object for per-scanner override thresholds
        )

        # ── AI Engines: PLSF + VSDE (Zero-Trust dual-engine) ──────────
        # PLSF: Psycho-Linguistic Sender Fingerprinting
        # Detects AI-generated BEC/impersonation via behavioral embedding drift
        self.plsf: Optional['PsychoLinguisticProfiler'] = None
        if _PLSF_AVAILABLE and getattr(self.cfg, 'plsf', None) and self.cfg.plsf.enabled:
            try:
                self.plsf = PsychoLinguisticProfiler(
                    db_path=self.cfg.plsf.db_path,
                )
                logger.info("✅ PLSF engine initialized (Zero-Trust BEC detection)")
            except Exception as exc:
                logger.warning("⚠️  PLSF init failed — BEC detection unavailable: %s", exc)
        elif _PLSF_AVAILABLE:
            # Fallback: initialize with defaults if settings section absent
            try:
                self.plsf = PsychoLinguisticProfiler()
                logger.info("✅ PLSF engine initialized (default config)")
            except Exception as exc:
                logger.warning("⚠️  PLSF init failed: %s", exc)

        # VSDE: Visual-Semantic Desynchronization Engine
        # Detects CSS overlay / zero-font / HTML-smuggling attacks via Jaccard desync
        # FIX-8: Pass evasion_threshold from VSDESettings so email.yaml config is honoured
        self.vsde: Optional['VisualDesyncScanner'] = None
        if _VSDE_AVAILABLE:
            try:
                vsde_threshold = 0.35  # default
                if getattr(self.cfg, 'vsde', None):
                    vsde_threshold = self.cfg.vsde.evasion_threshold
                self.vsde = VisualDesyncScanner()
                self.vsde.evasion_threshold = vsde_threshold
                logger.info(
                    "✅ VSDE engine initialized | threshold=%.2f",
                    vsde_threshold,
                )
            except Exception as exc:
                logger.warning("⚠️  VSDE init failed: %s", exc)

        logger.info("EmailInspectorPlugin initialized | enabled=%s | mode=%s",
                    self.cfg.enabled, self.cfg.mode)
        logger.info(self.cfg.summary())

    # ── InspectorPlugin interface ─────────────────────────────

    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Route email traffic automatically.

        Activates on any packet destined for or from an email port:
          SMTP: 25, 587, 465
          IMAP: 143, 993
          POP3: 110, 995
        OR configured Webmail HTTP POST requests.
        """
        # 🔴 Master switch
        if not self.cfg.enabled:
            return False

        ports = set(self.cfg.monitored_ports)
        if context.dst_port in ports or context.src_port in ports:
            return True

        # Check for Webmail HTTP POST/PUT requests using configured paths
        wm_cfg = getattr(self.cfg, "webmail_inspection", None)
        if wm_cfg and wm_cfg.enabled and hasattr(context, "http") and context.http and context.http.method in ("POST", "PUT"):
            path = context.http.path.lower()
            if any(kw in path for kw in wm_cfg.monitored_paths):
                return True

        return False

    async def initialize(self) -> None:
        logger.info("EmailInspectorPlugin ready | mode=%s", self.cfg.mode)

    async def shutdown(self) -> None:
        self._db_executor.shutdown(wait=False)
        logger.info("EmailInspectorPlugin shutdown")

    def inspect(self, context: InspectionContext, data: bytes = b"") -> InspectionResult:
        """
        Full email inspection pipeline.

        Returns InspectionResult with:
          - action:    ALLOW / QUARANTINE / BLOCK
          - findings:  List of InspectionFinding per detected threat
          - metadata:  risk_score, breakdown, phishing details, etc.
        """
        t_start = time.time()

        # ── Master switch ────────────────────────────────────────
        if not self.cfg.enabled:
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"email_security": "disabled"})

        # ── Whitelist CHECK ──────────────────────────────────────
        if self.cfg.is_whitelisted_sender(ip=context.src_ip):
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"email_security": "whitelisted"})

        findings: List[InspectionFinding] = []
        
        # For non-DATA SMTP commands (HELO, MAIL FROM, etc.) — minimal inspection
        command_penalty = 0.0
        sc_cfg = self.cfg.smtp_commands
        if sc_cfg.enabled:
            try:
                text = data.decode("utf-8", errors="ignore")
                first_word = text.strip().split()[0].upper() if text.strip() else ""
                if first_word in set(sc_cfg.suspicious_commands):
                    command_penalty = 0.3
                    findings.append(InspectionFinding(
                        plugin_name="email_smtp_commands",
                        severity="MEDIUM",
                        category="Email: Suspicious SMTP Command",
                        description=f"Suspicious SMTP command detected: {first_word}",
                        confidence=0.8,
                        recommends_block=False,
                    ))
            except Exception:
                pass

        # ── 1. PARSE EMAIL ──────────────────────────────────────
        raw_email = context.metadata.get("raw_email_bytes", data) if context and hasattr(context, "metadata") else data
        
        # Check if traffic is HTTP Webmail POST/PUT
        wm_cfg = getattr(self.cfg, "webmail_inspection", None)
        is_http_webmail = context and hasattr(context, "http") and context.http and context.http.method in ("POST", "PUT")
        if not is_http_webmail and raw_email and (raw_email.startswith(b"POST ") or raw_email.startswith(b"PUT ")):
            is_http_webmail = True

        if is_http_webmail and context and hasattr(context, "http") and context.http and context.http.body:
            try:
                http_body = context.http.body
                body_str = http_body.decode("utf-8", errors="ignore") if isinstance(http_body, bytes) else str(http_body)
                import urllib.parse
                unquoted_body = urllib.parse.unquote_plus(body_str)
                domain = wm_cfg.default_domain if wm_cfg else "organization.local"
                raw_email = (
                    f"From: webmail@{domain}\r\n"
                    f"To: recipient@{domain}\r\n"
                    "Subject: Webmail Transmission\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n\r\n"
                    + unquoted_body
                ).encode("utf-8")
            except Exception as _wbm_exc:
                logger.debug("Webmail body extraction failed: %s", _wbm_exc)

        parsed = None
        if self.cfg.preprocessing.enabled:
            parsed = self.preprocessor.parse(raw_email)
            if parsed is None and raw_email != data:
                parsed = self.preprocessor.parse(data)

        if parsed is None:
            # Not parseable as email — could be raw SMTP handshake
            # Return ALLOW with minimal metadata (let other plugins handle)
            return InspectionResult(
                action=InspectionAction.ALLOW,
                findings=findings,
                metadata={"email_security": "not_email_data",
                          "command_penalty": command_penalty},
            )

        # Check sender whitelist
        if self.cfg.is_whitelisted_sender(
            email=parsed.raw_from,
            domain=self._extract_domain(parsed.raw_from),
        ):
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"email_security": "whitelisted_sender"})

        # ── 2. PHISHING DETECTION ───────────────────────────────
        phishing_score = 0.0
        if self.cfg.phishing.enabled:
            ph_result = self.phishing_detector.detect(
                subject = parsed.subject,
                body    = parsed.body_text,
                urls    = parsed.urls,
            )
            phishing_score = ph_result.score

            if ph_result.decision in ("phishing", "suspicious"):
                findings.append(InspectionFinding(
                    plugin_name="email_phishing",
                    severity="CRITICAL" if ph_result.decision == "phishing" else "HIGH",
                    category=f"Email: Phishing ({ph_result.decision.title()})",
                    description=(
                        f"Phishing indicators found (score={ph_result.score:.2f}). "
                        f"Keywords: {', '.join(ph_result.matched_keywords[:5])}"
                        + (f" | Brand spoof: {ph_result.brand_spoof}" if ph_result.brand_spoof else "")
                    ),
                    confidence=ph_result.score,
                    recommends_block=ph_result.decision == "phishing",
                    metadata={
                        "phishing_score":    ph_result.score,
                        "matched_keywords":  ph_result.matched_keywords,
                        "brand_spoof":       ph_result.brand_spoof,
                        "urgency_flags":     ph_result.urgency_flags,
                    },
                ))

        # ── 3. URL SCANNING ─────────────────────────────────────
        url_score = 0.0
        if self.cfg.url_scanner.enabled and parsed.urls:
            url_result = self.url_scanner.scan(parsed.urls)
            url_score   = url_result.score

            if url_result.flagged_urls or url_result.excessive_urls:
                findings.append(InspectionFinding(
                    plugin_name="email_url_scanner",
                    severity="HIGH" if url_score > 0.6 else "MEDIUM",
                    category="Email: Malicious URL",
                    description=(
                        f"{len(url_result.flagged_urls)} suspicious URL(s) found. "
                        f"Total URLs: {url_result.total_urls}"
                        + (" (EXCESSIVE)" if url_result.excessive_urls else "")
                    ),
                    confidence=url_score,
                    recommends_block=url_score > 0.7,
                    metadata={
                        "url_score":     url_score,
                        "total_urls":    url_result.total_urls,
                        "flagged_urls":  [
                            {"url": s.url[:80], "flags": s.flags}
                            for s in url_result.flagged_urls[:5]
                        ],
                    },
                ))

        # ── 4. ATTACHMENT GUARD ─────────────────────────────────
        attachment_score = 0.0
        force_block      = False
        if self.cfg.attachment_guard.enabled and parsed.attachments:
            att_result      = self.attachment_guard.scan(parsed.attachments)
            attachment_score = att_result.score
            force_block     = att_result.blocked

            if att_result.findings:
                worst = att_result.findings[0]
                findings.append(InspectionFinding(
                    plugin_name="email_attachment_guard",
                    severity="CRITICAL" if force_block else "HIGH",
                    category="Email: Dangerous Attachment",
                    description=(
                        f"Suspicious attachment: {worst.filename} "
                        f"({', '.join(worst.flags)})"
                    ),
                    confidence=attachment_score,
                    recommends_block=force_block,
                    metadata={
                        "attachment_score": attachment_score,
                        "attachments": [
                            {"filename": f.filename, "flags": f.flags, "score": f.score}
                            for f in att_result.findings[:5]
                        ],
                    },
                ))

        # ── 5. SENDER REPUTATION ────────────────────────────────
        sender_score = 0.0
        if self.cfg.sender_reputation.enabled:
            sr_result    = self.sender_reputation.check(parsed, raw_email_bytes=data)
            sender_score = sr_result.score

            if sr_result.flags:
                findings.append(InspectionFinding(
                    plugin_name="email_sender_reputation",
                    severity="HIGH" if sender_score > 0.5 else "MEDIUM",
                    category="Email: Sender Reputation",
                    description=f"Sender reputation issues: {', '.join(sr_result.flags[:3])}",
                    confidence=sender_score,
                    recommends_block=sender_score > 0.7,
                    metadata={
                        "sender_score":  sender_score,
                        "spf_status":   sr_result.spf_status,
                        "dkim_present": sr_result.dkim_present,
                        "dkim_valid":   getattr(sr_result, 'dkim_valid', False),
                        "dmarc_policy": sr_result.dmarc_policy,
                        "is_disposable":sr_result.is_disposable,
                        "flags":        sr_result.flags,
                    },
                ))

        # ── 6. SPAM FILTER ──────────────────────────────────────
        spam_score = 0.0
        if self.cfg.spam_filter.enabled:
            sf_result  = self.spam_filter.score(
                subject   = parsed.subject,
                body_text = parsed.body_text,
                body_html = parsed.body_html,
            )
            spam_score = sf_result.score

            if sf_result.decision == "spam":
                findings.append(InspectionFinding(
                    plugin_name="email_spam_filter",
                    severity="MEDIUM",
                    category="Email: Spam",
                    description=(
                        f"Spam detected (score={sf_result.score:.2f}). "
                        f"Keywords: {', '.join(sf_result.matched_keywords[:4])}"
                    ),
                    confidence=sf_result.score,
                    recommends_block=False,
                    metadata={
                        "spam_score":       sf_result.score,
                        "matched_keywords": sf_result.matched_keywords,
                        "flags":            sf_result.flags,
                    },
                ))

        # ── 7. PLSF — Psycho-Linguistic Sender Fingerprinting ──────────
        # Detects AI-generated BEC impersonation via behavioral embedding + lexical BEC scan
        # Calibrated threshold λ_opt = 0.442 (Youden's J, Dataset v3.0)
        plsf_score = 0.0
        if self.plsf and parsed.raw_from and parsed.body_text:
            try:
                plsf_result = self.plsf.analyze(parsed.raw_from, parsed.body_text)
                plsf_score  = plsf_result.get("anomaly_score", 0.0)

                if plsf_result.get("is_suspected_mimicry", False):
                    findings.append(InspectionFinding(
                        plugin_name="email_plsf",
                        severity="CRITICAL",
                        category="Email: AI-Mimicry / BEC Detected (PLSF)",
                        description=(
                            f"Psycho-Linguistic fingerprint anomaly detected "
                            f"(composite_score={plsf_score:.3f} > λ_opt=0.442). "
                            f"{plsf_result.get('details', '')}"
                        ),
                        confidence=min(plsf_score, 1.0),
                        recommends_block=plsf_score > 0.70,
                        metadata={
                            "plsf_score":        plsf_score,
                            "semantic_deviation": plsf_result.get("semantic_deviation", 0.0),
                            "lexical_bec_score":  plsf_result.get("lexical_bec_score", 0.0),
                            "details":            plsf_result.get("details", ""),
                        },
                    ))
            except Exception as exc:
                logger.debug("PLSF analysis failed for %s: %s", parsed.raw_from[:30], exc)

        # ── 8. VSDE — Visual-Semantic Desynchronization Engine ─────────
        # Detects CSS overlay / zero-font / HTML-smuggling via Jaccard DOM-visual desync
        # Evasion threshold R > 0.35  →  BLOCK (force)
        vsde_score = 0.0
        if self.vsde and (parsed.body_html or parsed.body_text):
            try:
                mime_text = parsed.body_text or parsed.body_html
                html_body = parsed.body_html or parsed.body_text
                vsde_result = self.vsde.scan(mime_text, html_body)
                # FIX-VSDE: Use max(desync_ratio, 1.0 if direct_css_evasion) so
                # risk_engine.force_block fires even when ratio < 0.35 threshold
                _desync_ratio    = vsde_result.get("desync_ratio", 0.0)
                _direct_evasion  = vsde_result.get("direct_css_evasion", False)
                vsde_score = 1.0 if _direct_evasion else _desync_ratio

                if vsde_result.get("is_evasive", False) or _direct_evasion:
                    force_block = True
                    findings.append(InspectionFinding(
                        plugin_name="email_vsde",
                        severity="CRITICAL",
                        category="Email: CSS/HTML Visual Evasion Detected (VSDE)",
                        description=(
                            f"Visual-Semantic desync R={vsde_score:.3f} > 0.35. "
                            f"CSS overlay / zero-font / HTML-smuggling attack detected. "
                            f"{vsde_result.get('details', '')}"
                        ),
                        confidence=min(vsde_score, 1.0),
                        recommends_block=True,
                        metadata={
                            "vsde_score":    vsde_score,
                            "desync_ratio":  vsde_score,
                            "details":       vsde_result.get("details", ""),
                        },
                    ))
            except Exception as exc:
                logger.debug("VSDE analysis failed: %s", exc)

        # ── 9. RISK SCORING + POLICY DECISION ──────────────────
        breakdown = self.risk_engine.calculate(
            phishing_score   = phishing_score,
            url_score        = url_score,
            attachment_score = attachment_score,
            sender_score     = sender_score,
            spam_score       = spam_score,
            plsf_score       = plsf_score,
            vsde_score       = vsde_score,
            command_penalty  = command_penalty,
            force_block      = force_block,
        )

        # Map email decision to framework InspectionAction
        if not self.cfg.is_blocking:
            # Monitor mode: log only, never block
            action = InspectionAction.ALLOW
        elif breakdown.decision == EmailPolicyDecision.BLOCK:
            action = InspectionAction.BLOCK
        elif breakdown.decision == EmailPolicyDecision.QUARANTINE:
            action = InspectionAction.QUARANTINE
        else:
            action = InspectionAction.ALLOW

        latency_ms = (time.time() - t_start) * 1000

        logger.info(
            "Email [%s → %s] → %s (risk=%.2f) | latency=%.1fms",
            context.src_ip, context.dst_port,
            action.name, breakdown.final_score, latency_ms
        )
        logger.debug(
            "Email detail: from=%s subject=%s",
            parsed.raw_from[:20] + "***" if parsed.raw_from else "None", 
            parsed.subject[:20] + "***" if parsed.subject else "None"
        )

        self._inspected_count += 1
        if findings:
            self._detected_count += 1
        if action == InspectionAction.BLOCK:
            self._blocked_count += 1

        result = InspectionResult(
            action=action,
            findings=findings,
            processing_time_ms=latency_ms,
            metadata={
                "email_security":  True,
                "risk_score":      breakdown.final_score,
                "risk_decision":   breakdown.decision.value,
                "risk_breakdown":  breakdown.to_dict(),
                "from":            parsed.raw_from,
                "subject":         parsed.subject,
                "url_count":       len(parsed.urls),
                "attachment_count":len(parsed.attachments),
                "sender_ip":       parsed.sender_ip,
                "plsf_score":      round(plsf_score, 3),
                "vsde_score":      round(vsde_score, 3),
                "latency_ms":      round(latency_ms, 2),
            },
        )

        # Persist inspection result to DB — off the hot path
        self._db_executor.submit(
            self._log_to_db,
            context, parsed, breakdown, action, phishing_score, spam_score,
            url_score, attachment_score, sender_score, plsf_score,
            vsde_score, latency_ms, findings
        )
        
        if action in (InspectionAction.BLOCK, InspectionAction.QUARANTINE):
            try:
                EventBus.publish_from_thread(Topics.EMAIL_THREAT, {
                    "action":      action.name,
                    "risk_score":  breakdown.final_score,
                    "subject":     parsed.subject,
                    "sender":      parsed.raw_from,
                    "src_ip":      getattr(context, "src_ip", "") or getattr(context, "client_ip", ""),
                    "dst_ip":      getattr(context, "dst_ip", ""),
                    "threat_type": "email_threat",
                    "attack_type": "email_threat",
                    "severity":    "HIGH",
                    "description": f"Email threat blocked from {parsed.raw_from}",
                })
            except Exception as e:
                self.logger.debug("Failed to dispatch Email event: %s", e)

        return result

    def _log_to_db(self, context, parsed, breakdown, action, phishing_score,
                   spam_score, url_score, attachment_score, sender_score,
                   plsf_score, vsde_score, latency_ms, findings):
        """Persist an EmailLog entry. Called from a background thread.

        FIX-6: Removed blocking time.sleep() between retries to prevent
        thread-pool queue overflow under high load. Uses exponential backoff
        via a fresh connection per attempt instead.
        """
        MAX_ATTEMPTS = 3
        for attempt in range(MAX_ATTEMPTS):
            try:
                from system.database.database import SessionLocal
                from modules.email_security.models import EmailLog

                matched_kw = []
                flagged_urls_list = []
                brand_spoof = ""
                categories = []
                for f in findings:
                    categories.append(f.category)
                    md = getattr(f, "metadata", {}) or {}
                    matched_kw.extend(md.get("matched_keywords", []))
                    for u in md.get("flagged_urls", []):
                        flagged_urls_list.append(u.get("url", str(u)))
                    if md.get("phishing_score") and md.get("brand_spoof", ""):
                        brand_spoof = md["brand_spoof"]

                decision_str = breakdown.decision.value
                _PLSF_THREAT_THRESHOLD = getattr(self.cfg.plsf, 'lambda_opt', 0.442) \
                    if getattr(self.cfg, 'plsf', None) else 0.442

                with SessionLocal() as db:
                    from system.database.database import Base
                    import modules.email_security.models
                    try:
                        Base.metadata.create_all(bind=db.get_bind())
                    except Exception:
                        pass

                    log = EmailLog(
                        src_ip                   = context.src_ip,
                        dst_port                 = context.dst_port,
                        sender                   = parsed.raw_from[:255] if parsed.raw_from else None,
                        subject                  = parsed.subject[:512] if parsed.subject else None,
                        risk_score               = round(breakdown.final_score, 4),
                        phishing_score           = round(phishing_score, 4),
                        spam_score               = round(spam_score, 4),
                        url_score                = round(url_score, 4),
                        attachment_score         = round(attachment_score, 4),
                        sender_score             = round(sender_score, 4),
                        decision                 = decision_str,
                        is_phishing              = phishing_score >= 0.40,
                        is_spam                  = spam_score >= 0.70,
                        has_malicious_url        = url_score >= 0.40,
                        has_bad_attachment       = attachment_score >= 0.40,
                        is_ai_mimicry            = plsf_score >= _PLSF_THREAT_THRESHOLD,
                        linguistic_anomaly_score = round(plsf_score, 4),
                        has_visual_desync        = vsde_score > 0.35,
                        visual_desync_ratio      = round(vsde_score, 4),
                        brand_spoof              = brand_spoof[:64] if brand_spoof else None,
                        matched_keywords         = list(set(matched_kw))[:20],
                        flagged_urls             = flagged_urls_list[:10],
                        finding_categories       = categories,
                        latency_ms               = round(latency_ms, 2),
                    )
                    db.add(log)
                    db.commit()
                return  # success

            except Exception as exc:
                if attempt < MAX_ATTEMPTS - 1:
                    # Non-blocking: yield to other threads, no sleep()
                    import threading
                    threading.Event().wait(timeout=0.05 * (2 ** attempt))  # 50ms, 100ms
                    logger.debug("EmailLog retry %d after error: %s", attempt + 1, exc)
                else:
                    logger.error("EmailLog failed after %d attempts: %s", MAX_ATTEMPTS, exc)
                    logger.critical(
                        "AUDIT_LOSS | src=%s dst_port=%s decision=%s risk=%.2f "
                        "from=%s subject=%s",
                        context.src_ip, context.dst_port,
                        breakdown.decision.value, breakdown.final_score,
                        parsed.raw_from, parsed.subject,
                    )

    @staticmethod
    def _extract_domain(raw_from: str) -> str:
        m = _DOMAIN_RE.search(raw_from)
        return m.group(1).lower() if m else ""

