"""
Enterprise bunyanx — Email Spam Filter

Scores emails for spam characteristics using heuristics:
  1. Spam keyword density (expanded English + Arabic)
  2. Subject-line tricks (ALL CAPS, excessive punctuation!!!, [SPAM] markers)
  3. HTML vs text ratio (legit emails usually have both)
  4. Excessive whitespace / hidden text tricks
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)


_SPAM_KEYWORDS = [
    # English
    "you have won", "claim your prize", "limited time offer",
    "act now", "free money", "make money fast", "work from home",
    "no credit check", "earn extra cash", "guaranteed income",
    "lose weight", "weight loss", "diet pills", "click to unsubscribe",
    "this is not spam", "not a solicitation", "remove me from",
    "100% free", "risk-free", "money back guarantee", "no obligation",
    "free trial", "special promotion", "exclusive offer", "discount",
    "buy now", "order now", "click here", "visit our website",
    "dear friend", "dear user", "valued customer",
    # Arabic
    "اشترك الآن", "عرض حصري", "اربح الآن", "فرصة لا تفوتك",
    "اضغط هنا", "مجاناً تماماً", "اشتراك مجاني", "خسارة الوزن",
    "دخل إضافي", "العمل من المنزل", "ضمان استرداد المال",
]

_ALL_CAPS_PATTERN  = re.compile(r'\b[A-Z]{4,}\b')
_EXCESS_PUNCT      = re.compile(r'[!?]{2,}')
_SPAM_SUBJECT      = re.compile(r'^\s*(?:re:|fwd?:)?\s*(?:spam|bulk|unsolicited)', re.I)
_HIDDEN_TEXT       = re.compile(r'font-size\s*:\s*0|color\s*:\s*#fff|display\s*:\s*none', re.I)


@dataclass
class SpamFilterResult:
    score:            float = 0.0
    matched_keywords: List[str] = field(default_factory=list)
    flags:            List[str] = field(default_factory=list)
    decision:         str = "clean"   # clean | spam


class SpamFilter:
    """
    Lightweight heuristic spam filter.

    All scoring weights are read from SpamFilterSettings (email.yaml).

    Args:
        settings:          SpamFilterSettings from email.yaml
        keyword_threshold: Minimum keyword hits to flag as spam (legacy)
        spam_threshold:    Minimum score to mark as spam (legacy)
    """

    def __init__(
        self,
        settings=None,
        keyword_threshold: int   = 3,
        spam_threshold:    float = 0.70,
    ):
        if settings is not None:
            self.cfg = settings
        else:
            from modules.email_security.engine.core.settings import SpamFilterSettings
            self.cfg = SpamFilterSettings(
                keyword_threshold = keyword_threshold,
                spam_threshold    = spam_threshold,
            )
        self.keyword_threshold = self.cfg.keyword_threshold
        self.spam_threshold    = self.cfg.spam_threshold

    def score(self, subject: str, body_text: str, body_html: str) -> SpamFilterResult:
        """
        Score an email for spam.

        Args:
            subject:   Email subject
            body_text: Plain text body
            body_html: HTML body (raw, for structural tricks)
        """
        cfg     = self.cfg
        result  = SpamFilterResult()
        content = (subject + " " + body_text).lower()

        # 1. Keyword matching
        matched = [kw for kw in _SPAM_KEYWORDS if kw.lower() in content]
        result.matched_keywords = matched
        kw_score = min(len(matched) / max(cfg.keyword_threshold * 2, 1), 1.0)

        # 2. ALL CAPS words in subject (aggressive marketing)
        caps_hits = len(_ALL_CAPS_PATTERN.findall(subject))
        caps_score = min(caps_hits * cfg.caps_score_per_hit, cfg.caps_score_cap)
        if caps_hits > 2:
            result.flags.append(f"excessive_caps:{caps_hits}")

        # 3. Excessive punctuation in subject (!!! ???)
        punct_hits = len(_EXCESS_PUNCT.findall(subject))
        punct_score = min(punct_hits * cfg.punct_score_per_hit, cfg.punct_score_cap)
        if punct_hits:
            result.flags.append(f"excessive_punctuation:{punct_hits}")

        # 4. [SPAM] / [BULK] / [ADV] in subject
        if _SPAM_SUBJECT.match(subject):
            result.flags.append("spam_subject_prefix")
            result.score += cfg.spam_subject_prefix_score

        # 5. Hidden text in HTML (spammer evasion)
        hidden_hits = len(_HIDDEN_TEXT.findall(body_html))
        hidden_score = min(hidden_hits * cfg.hidden_score_per_hit, cfg.hidden_score_cap)
        if hidden_hits:
            result.flags.append(f"hidden_text:{hidden_hits}")

        # 6. Very short body with many formatting tricks
        if len(body_text.strip()) < 50 and len(body_html) > 500:
            result.flags.append("minimal_text_heavy_html")
            result.score += cfg.minimal_text_html_score

        # Aggregate
        result.score = min(
            result.score +
            (kw_score    * cfg.kw_weight) +
            (caps_score  * cfg.caps_weight) +
            (punct_score * cfg.punct_weight) +
            (hidden_score * cfg.hidden_weight),
            1.0
        )

        if result.score >= cfg.spam_threshold or len(matched) >= cfg.keyword_threshold:
            result.decision = "spam"

        return result
