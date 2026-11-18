"""
Enterprise bunyanx — Email Security Settings Loader

Reads `config/defaults/email.yaml` and merges with `config/email.local.yaml`.
Exposes typed settings for all email security layers.
Usage:
    from inspection.plugins.email.settings import get_email_settings
    cfg = get_email_settings()
    if cfg.enabled:
    cfg.set_enabled(False)   # runtime toggle, no restart needed
    cfg.set_mode("monitor")  # switch to shadow mode
    print(cfg.summary())
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

_DIR         = os.path.dirname(os.path.abspath(__file__))          # engine/core/
_ENGINE_DIR  = os.path.abspath(os.path.join(_DIR, ".."))           # engine/
_MODULE_DIR  = os.path.abspath(os.path.join(_ENGINE_DIR, ".."))    # email_security/

# Primary config: modules/email_security/config/email.yaml
DEFAULT_CONFIG = os.path.join(_MODULE_DIR, "config", "email.yaml")
# Local overrides: modules/email_security/config/email.local.yaml  (git-ignored)
LOCAL_CONFIG   = os.path.join(_MODULE_DIR, "config", "email.local.yaml")


# ── Sub-settings ──────────────────────────────


@dataclass
class PreprocessingSettings:
    enabled: bool = True
    decode_base64_body: bool = True
    decode_quoted_printable: bool = True
    extract_plain_text: bool = True
    max_body_bytes: int = 524288


@dataclass
class PhishingSettings:
    enabled: bool = True
    keyword_threshold: int = 2
    weight: float = 0.30
    custom_keywords: List[str] = field(default_factory=list)
    # NLP-based detection (optional — requires sentence-transformers)
    nlp_enabled: bool = False
    nlp_model_path: str = ""
    # Scoring sub-weights (sum = 1.0)
    keyword_weight:  float = 0.40
    urgency_weight:  float = 0.25
    spoof_weight:    float = 0.25
    url_excess_weight: float = 0.10
    # Per-signal coefficients
    urgency_score_per_hit:       float = 0.20
    urgency_score_cap:           float = 0.60
    spoof_score_value:           float = 0.70
    url_excess_threshold:        int   = 5
    url_excess_score_per_extra:  float = 0.05
    url_excess_score_cap:        float = 0.30
    # Decision thresholds
    phishing_hard_threshold: float = 0.70
    phishing_soft_threshold: float = 0.40



@dataclass
class URLScannerSettings:
    enabled: bool = True
    max_urls_per_email: int = 10
    reputation_check: bool = True
    detect_redirects: bool = True
    weight: float = 0.20
    trusted_domains: List[str] = field(default_factory=lambda: [
        "google.com", "microsoft.com", "github.com", "linkedin.com"
    ])
    # Per-signal scores
    score_ip_literal:           float = 0.50
    score_shortener:            float = 0.30
    score_suspicious_tld:       float = 0.30
    score_excessive_subdomains: float = 0.20
    score_very_long_url:        float = 0.10
    score_no_https:             float = 0.10
    threat_intel_weight:        float = 0.50
    flag_min_score:             float = 0.20
    excessive_url_penalty:      float = 0.20
    threat_intel_high:          float = 0.70
    threat_intel_medium:        float = 0.40


@dataclass
class AttachmentGuardSettings:
    enabled: bool = True
    max_attachment_size_mb: int = 25
    block_dangerous_extensions: bool = True
    entropy_analysis: bool = True
    entropy_threshold: float = 0.92
    weight: float = 0.15
    dangerous_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
        ".js", ".jar", ".msi", ".dll", ".ps1", ".psm1",
        ".hta", ".lnk", ".reg", ".inf",
    ])
    suspicious_extensions: List[str] = field(default_factory=lambda: [
        ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"
    ])
    # Per-signal scores
    score_dangerous_ext_blocked: float = 1.00
    score_dangerous_ext_allowed: float = 0.90
    score_suspicious_ext:        float = 0.40
    score_oversized:             float = 0.20
    score_high_entropy:          float = 0.35
    score_mime_mismatch:         float = 0.30
    action_block_threshold:      float = 0.80
    action_flag_threshold:       float = 0.40


@dataclass
class SenderReputationSettings:
    enabled: bool = True
    weight: float = 0.15
    spf_check: bool = True
    dkim_check: bool = True
    dmarc_check: bool = True
    block_disposable_domains: bool = True
    ip_reputation_check: bool = True
    custom_suspicious_domains: List[str] = field(default_factory=list)
    # Per-signal scores
    score_spf_fail:          float = 0.40
    score_spf_softfail:      float = 0.20
    score_no_dkim:           float = 0.15
    score_dkim_invalid:      float = 0.35
    score_dmarc_none:        float = 0.10
    score_dmarc_not_set:     float = 0.05
    score_disposable:        float = 0.50
    ip_reputation_threshold: float = 0.50
    ip_reputation_weight:    float = 0.40
    dns_lifetime_seconds:    float = 2.0
    dns_timeout_seconds:     float = 2.0
    ip_lookup_timeout:       float = 2.0


@dataclass
class SpamFilterSettings:
    enabled: bool = True
    weight: float = 0.05
    spam_threshold: float = 0.70
    keyword_threshold: int = 3
    # Scoring sub-weights
    kw_weight:     float = 0.50
    caps_weight:   float = 0.20
    punct_weight:  float = 0.15
    hidden_weight: float = 0.15
    # Per-signal coefficients
    caps_score_per_hit:        float = 0.08
    caps_score_cap:            float = 0.30
    punct_score_per_hit:       float = 0.10
    punct_score_cap:           float = 0.20
    hidden_score_per_hit:      float = 0.15
    hidden_score_cap:          float = 0.30
    spam_subject_prefix_score: float = 0.30
    minimal_text_html_score:   float = 0.15


@dataclass
class SMTPCommandSettings:
    enabled: bool = True
    weight: float = 0.05
    suspicious_commands: List[str] = field(
        default_factory=lambda: ["VRFY", "EXPN", "DEBUG"]
    )
    command_penalty: float = 0.30   # score penalty per suspicious command


@dataclass
class RiskThresholds:
    allow:      float = 0.15
    quarantine: float = 0.35
    block:      float = 0.65
    # Single High-Confidence Threat Overrides (read from risk_scoring section)
    phishing_block_threshold:        float = 0.70
    phishing_quarantine_threshold:   float = 0.40
    url_block_threshold:             float = 0.70
    url_quarantine_threshold:        float = 0.40
    attachment_quarantine_threshold: float = 0.40
    vsde_block_threshold:            float = 0.35
    plsf_quarantine_threshold:       float = 0.442
    plsf_block_threshold:            float = 0.70


@dataclass
class EmailLoggingSettings:
    enabled: bool = True
    log_blocked: bool = True
    log_quarantined: bool = True
    log_allowed: bool = False
    log_file: str = "data/logs/email_security.log"
    save_suspicious_content: bool = False


@dataclass
class AccessListSettings:
    enabled: bool = True
    emails:  List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips:     List[str] = field(default_factory=list)


# ── AI Engine Settings ─────────────────────────────────


@dataclass
class PLSFSettings:
    """
    Psycho-Linguistic Sender Fingerprinting (PLSF) engine settings.

    Model: all-MiniLM-L6-v2 (SentenceTransformer, 384-dim embeddings)
    Hybrid score: Score_composite = 0.40 × Dc + 0.60 × L_BEC
    Calibrated threshold: λ_opt = 0.442 (Youden's J — Dataset v3.0)
    """
    enabled:            bool  = True
    weight:             float = 0.10
    db_path:            str   = "modules/email_security/config/plsf_profiles_ai.db"
    # Youden-J calibrated optimal threshold (paper §V, Table 1)
    lambda_opt:         float = 0.442
    # EMA learning rate for baseline update (α in paper §IV-A)
    ema_alpha:          float = 0.10
    # Hybrid component weights (paper §IV-A Eq.3)
    w_semantic:         float = 0.40   # weight for Dc (cosine deviation)
    w_lexical:          float = 0.60   # weight for L_BEC (lexical BEC score)
    # Minimum messages before baseline is considered reliable
    min_baseline_count: int   = 3

    # ── Smart Routing & Multilingual Settings ──
    model_mode:              str   = "auto"      # auto, english_only, multilingual_only
    warmup_model:            str   = "en"       # en, multi
    min_routing_length:      int   = 10
    strict_language_routing: bool  = True
    max_models_in_memory:    int   = 2
    telemetry_level:         str   = "verbose"  # basic, verbose

@dataclass
class VSDESettings:
    """
    Visual-Semantic Desynchronization Engine (VSDE) settings.

    Algorithm: Jaccard distance between DOM/MIME token set and visual token set.
    Evasion detection threshold: R > 0.35  →  CSS/zero-font attack confirmed.
    """
    enabled:             bool  = True
    weight:              float = 0.15
    # Jaccard desync ratio above which the email is classified as evasive
    evasion_threshold:   float = 0.35
    # Headless browser render (requires playwright + Chromium)
    headless_browser:    bool  = False   # set True for production ViT rendering
    # Vision Transformer model for OCR (nlpconnect/vit-tiny)
    vit_model:           str   = "nlpconnect/vit-tiny"


@dataclass
class WebmailInspectionSettings:
    """Settings for inspecting HTTP Webmail form/JSON POST submissions."""
    enabled: bool = True
    default_domain: str = "company.local"
    monitored_paths: List[str] = field(
        default_factory=lambda: ["/webmail", "/mail", "/sendmail", "/api/v1/email", "/api/email", "/send"]
    )


# ── Master settings ────────────────────────────

@dataclass
class EmailSettings:
    """Master Email Security settings — loaded from email.yaml."""

    enabled:          bool     = True
    mode:             str      = "enforce"
    monitored_ports:  List[int] = field(
        default_factory=lambda: [25, 587, 465, 143, 993, 110, 995]
    )

    preprocessing:        PreprocessingSettings   = field(default_factory=PreprocessingSettings)
    phishing:             PhishingSettings         = field(default_factory=PhishingSettings)
    url_scanner:          URLScannerSettings       = field(default_factory=URLScannerSettings)
    attachment_guard:     AttachmentGuardSettings  = field(default_factory=AttachmentGuardSettings)
    sender_reputation:    SenderReputationSettings = field(default_factory=SenderReputationSettings)
    spam_filter:          SpamFilterSettings       = field(default_factory=SpamFilterSettings)
    smtp_commands:        SMTPCommandSettings      = field(default_factory=SMTPCommandSettings)
    # AI Engines
    plsf:                 PLSFSettings             = field(default_factory=PLSFSettings)
    vsde:                 VSDESettings             = field(default_factory=VSDESettings)
    webmail_inspection:   WebmailInspectionSettings = field(default_factory=WebmailInspectionSettings)
    thresholds:           RiskThresholds           = field(default_factory=RiskThresholds)
    logging:              EmailLoggingSettings     = field(default_factory=EmailLoggingSettings)
    whitelist:            AccessListSettings       = field(default_factory=AccessListSettings)

    _config_path: str = field(default=DEFAULT_CONFIG, repr=False)

    # ── Convenience ─────────────────────────────

    @property
    def is_blocking(self) -> bool:
        return self.enabled and self.mode == "enforce"

    def is_whitelisted_sender(self, email: str = "", domain: str = "", ip: str = "") -> bool:
        if not self.whitelist or not self.whitelist.enabled:
            return False
        emails  = self.whitelist.emails  or []
        domains = self.whitelist.domains or []
        ips     = self.whitelist.ips     or []
        if email and email.lower() in [e.lower() for e in emails if e]:
            return True
        if domain and domain.lower() in [d.lower() for d in domains if d]:
            return True
        if ip and ip in ips:
            return True
        return False

    # ── Runtime toggles ──────────────────────────

    def set_enabled(self, value: bool) -> None:
        self.enabled = value
        logger.warning("EmailSecurity master switch → %s", "ENABLED" if value else "DISABLED")

    def set_mode(self, mode: str) -> None:
        if mode not in ("enforce", "monitor", "learning"):
            raise ValueError(f"Invalid mode: {mode}")
        self.mode = mode
        logger.info("EmailSecurity mode → %s", mode)

    def reload(self) -> None:
        fresh = EmailSettings.load(self._config_path)
        self.__dict__.update(fresh.__dict__)
        logger.info("EmailSettings reloaded from %s", self._config_path)

    def summary(self) -> str:
        on = lambda v: "✅" if v else "❌"
        lines = [
            "══════════════════════════════════════════════",
            f"  Email Security : {'🟢 ENABLED' if self.enabled else '🔴 DISABLED'}",
            f"  Mode           : {self.mode.upper()}",
            "──────────────────────────────────────────────",
            f"  Preprocessing:   {on(self.preprocessing.enabled)}\n"
            f"  Phishing Detect: {on(self.phishing.enabled)}\n"
            f"  URL Scanner:     {on(self.url_scanner.enabled)}\n",
            f"  Attachment Guard: {on(self.attachment_guard.enabled)}",
            f"  Sender Repute  : {on(self.sender_reputation.enabled)}  (SPF={on(self.sender_reputation.spf_check)} DKIM={on(self.sender_reputation.dkim_check)})",
            f"  Spam Filter    : {on(self.spam_filter.enabled)}",
            f"  SMTP Commands  : {on(self.smtp_commands.enabled)}",
            "──────────────────────────────────────────────",
            f"  Block threshold: {self.thresholds.block:.0%}",
            "══════════════════════════════════════════════",
        ]
        return "\n".join(lines)

    # ── YAML Loader ──────────────────────────────

    @classmethod
    def load(cls, config_path: str = DEFAULT_CONFIG, local_path: str = LOCAL_CONFIG) -> "EmailSettings":
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML required: pip install pyyaml — using defaults")
            return cls()

        raw = {}
        if os.path.exists(config_path):
            with open(config_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            logger.info("Email config loaded from %s", config_path)
        else:
            logger.warning("Email config not found at %s — using defaults", config_path)

        if os.path.exists(local_path):
            with open(local_path, encoding="utf-8") as f:
                local_raw = yaml.safe_load(f) or {}
            raw = _deep_merge(raw, local_raw)
            logger.info("Email local overrides applied from %s", local_path)

        cfg = raw.get("email_security", {})
        return cls._from_dict(cfg)

    @classmethod
    def from_dict(cls, d: dict) -> "EmailSettings":
        """Public alias for _from_dict — used by router.py for hot-reload."""
        return cls._from_dict(d)

    @classmethod
    def _from_dict(cls, d: dict) -> "EmailSettings":
        s = cls()
        s.enabled         = d.get("enabled", True)
        s.mode            = d.get("mode", "enforce")
        s.monitored_ports = d.get("monitored_ports", s.monitored_ports)

        pp = d.get("preprocessing", {})
        s.preprocessing = PreprocessingSettings(
            enabled               = pp.get("enabled", True),
            decode_base64_body    = pp.get("decode_base64_body", True),
            decode_quoted_printable = pp.get("decode_quoted_printable", True),
            extract_plain_text    = pp.get("extract_plain_text", True),
            max_body_bytes        = pp.get("max_body_bytes", 524288),
        )

        ph = d.get("phishing_detection", d.get("phishing", {}))
        if ph:
            s.phishing = PhishingSettings(
                enabled           = ph.get("enabled", True),
                keyword_threshold = ph.get("keyword_threshold", 2),
                weight            = ph.get("weight", 0.30),
                custom_keywords   = ph.get("custom_keywords", []),
                # Scoring sub-weights
                keyword_weight    = ph.get("keyword_weight", 0.40),
                urgency_weight    = ph.get("urgency_weight", 0.25),
                spoof_weight      = ph.get("spoof_weight", 0.25),
                url_excess_weight = ph.get("url_excess_weight", 0.10),
                # Per-signal coefficients
                urgency_score_per_hit      = ph.get("urgency_score_per_hit", 0.20),
                urgency_score_cap          = ph.get("urgency_score_cap", 0.60),
                spoof_score_value          = ph.get("spoof_score_value", 0.70),
                url_excess_threshold       = ph.get("url_excess_threshold", 5),
                url_excess_score_per_extra = ph.get("url_excess_score_per_extra", 0.05),
                url_excess_score_cap       = ph.get("url_excess_score_cap", 0.30),
                # Decision thresholds
                phishing_hard_threshold = ph.get("phishing_hard_threshold", 0.70),
                phishing_soft_threshold = ph.get("phishing_soft_threshold", 0.40),
            )

        us = d.get("url_scanner", {})
        s.url_scanner = URLScannerSettings(
            enabled            = us.get("enabled", True),
            max_urls_per_email = us.get("max_urls_per_email", 10),
            reputation_check   = us.get("reputation_check", True),
            detect_redirects   = us.get("detect_redirects", True),
            weight             = us.get("weight", 0.20),
            trusted_domains    = us.get("trusted_domains", s.url_scanner.trusted_domains),
            # Per-signal scores
            score_ip_literal           = us.get("score_ip_literal", 0.50),
            score_shortener            = us.get("score_shortener", 0.30),
            score_suspicious_tld       = us.get("score_suspicious_tld", 0.30),
            score_excessive_subdomains = us.get("score_excessive_subdomains", 0.20),
            score_very_long_url        = us.get("score_very_long_url", 0.10),
            score_no_https             = us.get("score_no_https", 0.10),
            threat_intel_weight        = us.get("threat_intel_weight", 0.50),
            flag_min_score             = us.get("flag_min_score", 0.20),
            excessive_url_penalty      = us.get("excessive_url_penalty", 0.20),
            threat_intel_high          = us.get("threat_intel_high", 0.70),
            threat_intel_medium        = us.get("threat_intel_medium", 0.40),
        )

        ag = d.get("attachment_guard", {})
        s.attachment_guard = AttachmentGuardSettings(
            enabled                    = ag.get("enabled", True),
            max_attachment_size_mb     = ag.get("max_attachment_size_mb", 25),
            block_dangerous_extensions = ag.get("block_dangerous_extensions", True),
            entropy_analysis           = ag.get("entropy_analysis", True),
            entropy_threshold          = ag.get("entropy_threshold", 0.92),
            weight                     = ag.get("weight", 0.15),
            dangerous_extensions       = ag.get("dangerous_extensions", s.attachment_guard.dangerous_extensions),
            suspicious_extensions      = ag.get("suspicious_extensions", s.attachment_guard.suspicious_extensions),
            # Per-signal scores
            score_dangerous_ext_blocked = ag.get("score_dangerous_ext_blocked", 1.00),
            score_dangerous_ext_allowed = ag.get("score_dangerous_ext_allowed", 0.90),
            score_suspicious_ext        = ag.get("score_suspicious_ext", 0.40),
            score_oversized             = ag.get("score_oversized", 0.20),
            score_high_entropy          = ag.get("score_high_entropy", 0.35),
            score_mime_mismatch         = ag.get("score_mime_mismatch", 0.30),
            action_block_threshold      = ag.get("action_block_threshold", 0.80),
            action_flag_threshold       = ag.get("action_flag_threshold", 0.40),
        )

        sr = d.get("sender_reputation", {})
        s.sender_reputation = SenderReputationSettings(
            enabled                   = sr.get("enabled", True),
            weight                    = sr.get("weight", 0.15),
            spf_check                 = sr.get("spf_check", True),
            dkim_check                = sr.get("dkim_check", True),
            dmarc_check               = sr.get("dmarc_check", True),
            block_disposable_domains  = sr.get("block_disposable_domains", True),
            ip_reputation_check       = sr.get("ip_reputation_check", True),
            custom_suspicious_domains = sr.get("custom_suspicious_domains", []),
            # Per-signal scores
            score_spf_fail          = sr.get("score_spf_fail", 0.40),
            score_spf_softfail      = sr.get("score_spf_softfail", 0.20),
            score_no_dkim           = sr.get("score_no_dkim", 0.0),
            score_dkim_invalid      = sr.get("score_dkim_invalid", 0.35),
            score_dmarc_none        = sr.get("score_dmarc_none", 0.10),
            score_dmarc_not_set     = sr.get("score_dmarc_not_set", 0.05),
            score_disposable        = sr.get("score_disposable", 0.50),
            ip_reputation_threshold = sr.get("ip_reputation_threshold", 0.50),
            ip_reputation_weight    = sr.get("ip_reputation_weight", 0.40),
            dns_lifetime_seconds    = sr.get("dns_lifetime_seconds", 2.0),
            dns_timeout_seconds     = sr.get("dns_timeout_seconds", 2.0),
            ip_lookup_timeout       = sr.get("ip_lookup_timeout", 2.0),
        )

        sf = d.get("spam_filter", {})
        s.spam_filter = SpamFilterSettings(
            enabled           = sf.get("enabled", True),
            weight            = sf.get("weight", 0.05),
            spam_threshold    = sf.get("spam_threshold", 0.70),
            keyword_threshold = sf.get("keyword_threshold", 3),
            # Scoring sub-weights
            kw_weight     = sf.get("kw_weight", 0.50),
            caps_weight   = sf.get("caps_weight", 0.20),
            punct_weight  = sf.get("punct_weight", 0.15),
            hidden_weight = sf.get("hidden_weight", 0.15),
            # Per-signal coefficients
            caps_score_per_hit        = sf.get("caps_score_per_hit", 0.08),
            caps_score_cap            = sf.get("caps_score_cap", 0.30),
            punct_score_per_hit       = sf.get("punct_score_per_hit", 0.10),
            punct_score_cap           = sf.get("punct_score_cap", 0.20),
            hidden_score_per_hit      = sf.get("hidden_score_per_hit", 0.15),
            hidden_score_cap          = sf.get("hidden_score_cap", 0.30),
            spam_subject_prefix_score = sf.get("spam_subject_prefix_score", 0.30),
            minimal_text_html_score   = sf.get("minimal_text_html_score", 0.15),
        )

        sc = d.get("smtp_commands", {})
        s.smtp_commands = SMTPCommandSettings(
            enabled             = sc.get("enabled", True),
            weight              = sc.get("weight", 0.05),
            suspicious_commands = sc.get("suspicious_commands", ["VRFY", "EXPN", "DEBUG"]),
            command_penalty     = sc.get("command_penalty", 0.30),
        )

        # ── PLSF (Psycho-Linguistic Sender Fingerprinting) ──────────
        pl = d.get("plsf_config", d.get("plsf", {}))
        s.plsf = PLSFSettings(
            enabled            = pl.get("enabled",            True),
            weight             = pl.get("weight",             0.10),
            db_path            = pl.get("db_path",            s.plsf.db_path),
            lambda_opt         = pl.get("lambda_opt",         0.442),
            ema_alpha          = pl.get("ema_alpha",          0.10),
            w_semantic         = pl.get("w_semantic",         0.40),
            w_lexical          = pl.get("w_lexical",          0.60),
            min_baseline_count = pl.get("min_baseline_count", 3),
            model_mode         = pl.get("model_mode", "auto"),
            warmup_model       = pl.get("warmup_model", "en"),
            min_routing_length = pl.get("min_routing_length", 10),
            strict_language_routing = pl.get("strict_language_routing", True),
            max_models_in_memory = pl.get("max_models_in_memory", 2),
            telemetry_level    = pl.get("telemetry_level", "verbose"),
        )

        # ── VSDE (Visual-Semantic Desynchronization Engine) ─────────
        vs = d.get("vsde_config", d.get("vsde", {}))
        s.vsde = VSDESettings(
            enabled           = vs.get("enabled",           True),
            weight            = vs.get("weight",            0.15),
            evasion_threshold = vs.get("evasion_threshold", 0.35),
            headless_browser  = vs.get("headless_browser",  False),
            vit_model         = vs.get("vit_model",         "nlpconnect/vit-tiny"),
        )

        # ── Webmail Inspection ──────────────────────────────────────
        wm = d.get("webmail_inspection", {})
        s.webmail_inspection = WebmailInspectionSettings(
            enabled         = wm.get("enabled", True),
            default_domain  = wm.get("default_domain", "organization.local"),
            monitored_paths = wm.get("monitored_paths", ["/webmail", "/mail", "/sendmail", "/api/v1/email", "/api/email", "/send"]),
        )

        thr_section = d.get("risk_scoring", {})
        thr = thr_section.get("thresholds", {})
        s.thresholds = RiskThresholds(
            allow      = thr.get("allow",      0.15),
            quarantine = thr.get("quarantine",  0.35),
            block      = thr.get("block",       0.65),
            # Single High-Confidence Threat Override thresholds
            phishing_block_threshold        = thr_section.get("phishing_block_threshold",        0.70),
            phishing_quarantine_threshold   = thr_section.get("phishing_quarantine_threshold",   0.40),
            url_block_threshold             = thr_section.get("url_block_threshold",             0.70),
            url_quarantine_threshold        = thr_section.get("url_quarantine_threshold",        0.40),
            attachment_quarantine_threshold = thr_section.get("attachment_quarantine_threshold", 0.40),
            vsde_block_threshold            = thr_section.get("vsde_block_threshold",            0.35),
            plsf_quarantine_threshold       = thr_section.get("plsf_quarantine_threshold",       0.442),
            plsf_block_threshold            = thr_section.get("plsf_block_threshold",            0.70),
        )

        lg = d.get("logging", {})
        s.logging = EmailLoggingSettings(
            enabled                 = lg.get("enabled", True),
            log_blocked             = lg.get("log_blocked", True),
            log_quarantined         = lg.get("log_quarantined", True),
            log_allowed             = lg.get("log_allowed", False),
            log_file                = lg.get("log_file", s.logging.log_file),
            save_suspicious_content = lg.get("save_suspicious_content", False),
        )

        wl = d.get("whitelist", {})
        s.whitelist = AccessListSettings(
            enabled = wl.get("enabled", True),
            emails  = wl.get("emails",  []),
            domains = wl.get("domains", []),
            ips     = wl.get("ips",     []),
        )

        return s


# ── Singleton ─────────────────────────────────
import threading
_lock = threading.Lock()
_instance: Optional[EmailSettings] = None

def get_email_settings() -> EmailSettings:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = EmailSettings.load()
    return _instance


def reload_singleton() -> EmailSettings:
    """Force reload of global settings singleton from YAML. Called after config updates."""
    global _instance
    with _lock:
        _instance = EmailSettings.load()
    return _instance


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
