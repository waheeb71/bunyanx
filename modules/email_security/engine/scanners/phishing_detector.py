"""
Enterprise bunyanx — Phishing Detector

Detects phishing attempts in email subject + body using:
  1. Keyword heuristics (expanded multilingual list)
  2. Urgency / social-engineering pattern matching
  3. Domain spoofing indicators (brand name ≠ link domain)
  4. Optional: NLP model inference (same architecture as WAF NLP)

All scoring coefficients are driven by email.yaml — no hardcoded values.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional
from modules.email_security.engine.core.settings import PhishingSettings

logger = logging.getLogger(__name__)

# ── Phishing keyword lists ───────────────────────────────────────────
# (English and Arabic combined — most phishing campaigns use both)

_PHISHING_KEYWORDS = [
    # Account security / urgency
    "verify your account", "verify your credentials", "confirm your identity", "suspended account",
    "unusual activity", "unusual login attempt", "unauthorized access", "account locked", "account compromised",
    "click here immediately", "urgent action required", "act immediately", "temporarily suspended",
    "reactivate your account", "secure verification link", "national id number", "credit card number",
    "one-time password", "final notice", "last warning",
    # Credentials / password
    "reset your password", "update your credentials", "change your password",
    "confirm your email", "validate your account",
    # Financial
    "wire transfer", "wire payment", "immediate wire", "bank account", "credit card", "invoice attached",
    "payment failed", "refund available", "transaction declined",
    # Prizes / social engineering
    "you have won", "congratulations", "claim your reward",
    "you are selected", "lucky winner",
    # Crypto / scam
    "bitcoin", "cryptocurrency", "investment opportunity",
    "double your money", "high returns",
    # Arabic phishing keywords
    "تحقق من حسابك", "تأكيد هويتك", "تم تعليق حسابك", "تعليق حسابك", "حسابك البنكي",
    "محاولة دخول غير معتادة", "تنشيط حسابك", "رقم الهوية الوطنية", "رقم بطاقة الائتمان",
    "نشاط غير معتاد", "انقر هنا فوراً", "إجراء عاجل",
    "إعادة تعيين كلمة المرور", "تحديث بياناتك",
    "تحويل بنكي", "فاتورة مرفقة", "فرصة استثمارية",
]

# ── Brand impersonation — brand name → common legit domains
_BRAND_DOMAINS = {
    "paypal":        ["paypal.com"],
    "apple":         ["apple.com", "icloud.com"],
    "microsoft":     ["microsoft.com", "live.com", "outlook.com", "hotmail.com"],
    "google":        ["google.com", "gmail.com", "accounts.google.com"],
    "amazon":        ["amazon.com", "amazon.co.uk", "amazon.de"],
    "facebook":      ["facebook.com", "fb.com"],
    "netflix":       ["netflix.com"],
    "dhl":           ["dhl.com", "dhl.de"],
    "fedex":         ["fedex.com"],
    "stcpay":        ["stcpay.com.sa"],
    "riyad bank":    ["riyadbank.com"],
    "riyadbank":     ["riyadbank.com"],
    "alrajhi":       ["alrajhibank.com.sa"],
    "rajhi bank":    ["alrajhibank.com.sa"],
    "snb":           ["alabali.com", "snb.com.sa"],
    "ncb":           ["alabali.com"],
    "alinma":        ["alinma.com"],
    "bsf":           ["alfransi.com.sa"],
    "sab":           ["sabb.com"],
    "anb":           ["anb.com.sa"],
    "safat":         ["gov.sa"],
}

# ── Urgency / social engineering patterns ───────────────────────────
_URGENCY_PATTERNS = [
    re.compile(r"\b(within\s+\d+\s+hours?|خلال\s+\d+\s+ساعة|within\s+24h)\b", re.I),
    re.compile(r"\b(immediately|فوراً|urgently|عاجل)\b", re.I),
    re.compile(r"\b(account.{0,20}(suspend|terminat|delet|block))", re.I),
    re.compile(r"\b(click.{0,30}link|انقر.{0,30}الرابط)\b", re.I),
]

_DOMAIN_PATTERN = re.compile(r'https?://([^/\s<>"\']+)', re.I)


@dataclass
class PhishingResult:
    score:            float = 0.0          # 0.0=clean, 1.0=definite phishing
    matched_keywords: List[str] = None
    urgency_flags:    int = 0
    brand_spoof:      str = ""             # e.g. "paypal" spoofed
    decision:         str = "clean"        # clean | suspicious | phishing

    def __post_init__(self):
        if self.matched_keywords is None:
            self.matched_keywords = []


class PhishingDetector:
    """
    AI-enhanced phishing detector.

    All scoring weights and thresholds are driven by PhishingSettings
    loaded from email.yaml — no hardcoded values in this class.

    Args:
        settings:          PhishingSettings (from email.yaml)
        custom_keywords:   Additional site-specific phishing keywords
    """

    def __init__(
        self,
        settings:          Optional[PhishingSettings] = None,
        # Legacy positional args kept for backward compatibility
        keyword_threshold: int = 2,
        nlp_enabled:       bool = False,
        nlp_model_path:    str  = "",
        custom_keywords:   Optional[List[str]] = None,
    ):
        # Prefer settings object; fall back to individual args
        if settings is not None:
            self.cfg = settings
        else:
            from modules.email_security.engine.core.settings import PhishingSettings
            self.cfg = PhishingSettings(
                keyword_threshold = keyword_threshold,
                nlp_enabled       = nlp_enabled,
                nlp_model_path    = nlp_model_path,
                custom_keywords   = list(custom_keywords or []),
            )

        self.keyword_threshold = self.cfg.keyword_threshold
        self._keywords = list(_PHISHING_KEYWORDS) + (self.cfg.custom_keywords or [])

        if self.cfg.nlp_enabled:
            logger.warning(
                "PhishingDetector: nlp_enabled=True but NLP pipeline is not yet "
                "implemented — falling back to keyword+heuristic detection."
            )

    def detect(self, subject: str, body: str, urls: List[str]) -> PhishingResult:
        """
        Analyse email content for phishing.

        Args:
            subject: Email subject line
            body:    Plain text body
            urls:    All URLs extracted from the email

        Returns:
            PhishingResult with score, matched keywords, and decision
        """
        content = (subject + " " + body).lower()
        result  = PhishingResult()
        cfg     = self.cfg

        # ── 1. Keyword matching ──────────────────────
        matched = [kw for kw in self._keywords if kw.lower() in content]
        result.matched_keywords = matched

        keyword_score = min(len(matched) / max(cfg.keyword_threshold * 2, 1), 1.0)

        # ── 2. Urgency patterns ──────────────────────
        urgency_hits = sum(1 for p in _URGENCY_PATTERNS if p.search(content))
        result.urgency_flags = urgency_hits
        urgency_score = min(urgency_hits * cfg.urgency_score_per_hit, cfg.urgency_score_cap)

        # ── 3. Brand spoofing: brand name in body ≠ URL domain ──
        spoof_score = 0.0
        for brand, legit_domains in _BRAND_DOMAINS.items():
            if brand in content:
                link_domains = [
                    m.group(1).lower().split("/")[0]
                    for m in _DOMAIN_PATTERN.finditer(content)
                ]
                # FIX-BRAND-SPOOF: check that link domain IS the legit domain
                # (not that legit domain is a substring of attack domain)
                # e.g. "paypal.com" ∈ "paypal-security-update.com" was FALSE NEGATIVE
                if link_domains and not any(
                    any(d == ld or d.endswith("." + ld) for ld in legit_domains)
                    for d in link_domains
                ):
                    result.brand_spoof = brand
                    spoof_score = cfg.spoof_score_value
                    break

        # ── 4. Excessive URLs ────────────────────────
        url_excess_score = 0.0
        if len(urls) > cfg.url_excess_threshold:
            url_excess_score = min(
                (len(urls) - cfg.url_excess_threshold) * cfg.url_excess_score_per_extra,
                cfg.url_excess_score_cap,
            )

        # ── Aggregate ────────────────────────────────
        result.score = min(
            (keyword_score    * cfg.keyword_weight) +
            (urgency_score    * cfg.urgency_weight) +
            (spoof_score      * cfg.spoof_weight) +
            (url_excess_score * cfg.url_excess_weight),
            1.0
        )

        # ── Decision ─────────────────────────────────
        if result.score >= cfg.phishing_hard_threshold or (
            len(matched) >= cfg.keyword_threshold and spoof_score > 0
        ):
            result.decision = "phishing"
        elif result.score >= cfg.phishing_soft_threshold or len(matched) >= cfg.keyword_threshold:
            result.decision = "suspicious"
        else:
            result.decision = "clean"

        return result
