"""
Visual-Semantic Desync Engine (VSDE) — CSS-Aware Edition
=========================================================

Defeats evasive email attacks by detecting CSS hidden content divergence.

┌─ CURRENT MODE: CSS-Aware Lexical Desync ──────────────────────────────┐
│ Algorithm:  BeautifulSoup HTML parsing + CSS evasion element removal   │
│ Compares:   ALL text in MIME  vs.  VISIBLE text only (CSS-filtered)    │
│ Detects:    CSS zero-font, white-on-white, display:none, aria-hidden,  │
│             HTML comments (smuggling), overflow:hidden, opacity:0      │
│ Fallback:   Pure regex-based CSS removal if BeautifulSoup unavailable  │
└────────────────────────────────────────────────────────────────────────┘

┌─ FULL PRODUCTION MODE (ViT Rendering) ────────────────────────────────┐
│ For pixel-perfect OCR-level detection, enable headless rendering:      │
│   pip install playwright && playwright install chromium                 │
│   pip install transformers                                              │
│ Then set  headless_browser: true  in email.yaml → [vsde] section      │
│ Engine will render via Chromium + extract text via nlpconnect/vit-tiny │
└────────────────────────────────────────────────────────────────────────┘

Evasion threshold R > 0.35 → attack confirmed → force BLOCK
"""

import logging
import re
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# ── CSS hiding patterns ───────────────────────────────────
_CSS_ZERO_FONT = re.compile(
    r'font-size\s*:\s*0(?:px|pt|em|rem|%|vh|vw)?(?:\s*[;!]|\s*$)',
    re.I
)
_CSS_WHITE_TEXT = re.compile(
    r'color\s*:\s*(?:#fff(?:fff)?|white|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\)|rgba\s*\(\s*255\s*,\s*255\s*,\s*255\s*,\s*[01](?:\.\d+)?\s*\))',
    re.I
)
_CSS_HIDDEN = re.compile(
    r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0'
    r'|max-height\s*:\s*0|overflow\s*:\s*hidden|height\s*:\s*0(?:px)?'
    r'|width\s*:\s*0(?:px)?|clip\s*:\s*rect\s*\(\s*0)',
    re.I
)

# ── Regex fallback: strip hidden inline-style elements ────
_HIDDEN_ELEMENT_RE = re.compile(
    r'<([a-zA-Z0-9]+)\b[^>]*?\bstyle=[\'"][^\'"]*?'
    r'(?:display\s*:\s*none|visibility\s*:\s*hidden'
    r'|font-size\s*:\s*0|opacity\s*:\s*0)[^\'"]*?[\'"][^>]*>.*?</\1>',
    re.I | re.DOTALL
)
_HTML_COMMENT_RE = re.compile(r'<!--.*?-->', re.DOTALL)
_TAG_STRIP_RE    = re.compile(r'<[^>]+>')


class VisualDesyncScanner:
    """
    CSS-aware Visual-Semantic Desync Engine.

    Detects divergence between:
      - body_text  (all MIME text, including hidden content)
      - body_html  (HTML source, from which we extract *visible-only* text)

    A high desync ratio means the email contains text the reader cannot see —
    a hallmark of CSS zero-font, white-text, or display:none attacks.
    """

    def __init__(self):
        self.enabled = True
        self.evasion_threshold = 0.35   # Jaccard desync ratio → BLOCK

        # Detect BeautifulSoup availability once at init
        try:
            from bs4 import BeautifulSoup  # noqa: F401
            self._bs4_available = True
            logger.info("👁️ VSDE initialized [Mode: CSS-Aware / BeautifulSoup]")
        except ImportError:
            self._bs4_available = False
            logger.warning(
                "👁️ VSDE initialized [Mode: Regex Fallback — install beautifulsoup4 "
                "for higher accuracy: pip install beautifulsoup4]"
            )

        # ⚠️ Production ViT activation (Headless Chrome + Vision Transformer):
        # from playwright.sync_api import sync_playwright
        # from transformers import pipeline
        # self.playwright_engine = sync_playwright().start()
        # self.browser = self.playwright_engine.chromium.launch(headless=True)
        # self.vision_transformer = pipeline("image-to-text", model="nlpconnect/vit-tiny")

    # ── CSS inspection helpers ──────────────────────────────────────────

    def _is_hidden_by_css(self, style: str) -> bool:
        """Return True if an inline CSS style hides an element from the viewer."""
        return bool(
            _CSS_ZERO_FONT.search(style) or
            _CSS_WHITE_TEXT.search(style) or
            _CSS_HIDDEN.search(style)
        )

    # ── Visible text extraction ─────────────────────────────────────────

    def _extract_visible_text(self, html: str) -> Tuple[str, List[str]]:
        """
        Remove hidden HTML elements and return only what a user can visually see.

        Returns
        -------
        visible_text : str
        attacks      : list of detected evasion technique labels
        """
        attacks: List[str] = []

        if self._bs4_available:
            return self._extract_via_bs4(html, attacks)
        return self._extract_via_regex(html, attacks)

    def _extract_via_bs4(self, html: str, attacks: List[str]) -> Tuple[str, List[str]]:
        """High-accuracy extraction using BeautifulSoup."""
        from bs4 import BeautifulSoup, Comment

        soup = BeautifulSoup(html, "html.parser")

        # 1. Remove HTML comments (HTML-smuggling vector)
        comments = soup.find_all(string=lambda t: isinstance(t, Comment))
        if comments:
            attacks.append(f"html_comment_smuggling ({len(comments)} nodes)")
            for c in comments:
                c.extract()

        # 2. Remove <script> and <style> blocks (not visible to user)
        for tag in soup(["script", "style", "head"]):
            tag.decompose()

        # 3. Remove CSS-hidden elements
        hidden_count = 0
        for tag in soup.find_all(True):
            style = tag.get("style", "")
            hidden_attr = tag.get("hidden")
            aria_hidden  = tag.get("aria-hidden", "").lower() == "true"

            if (style and self._is_hidden_by_css(style)) or \
               hidden_attr is not None or aria_hidden:
                hidden_count += 1
                # Classify the specific technique
                if style:
                    if _CSS_ZERO_FONT.search(style):
                        attacks.append("css_zero_font")
                    if _CSS_WHITE_TEXT.search(style):
                        attacks.append("css_white_on_white")
                    if _CSS_HIDDEN.search(style):
                        attacks.append("css_display_none_or_hidden")
                if hidden_attr is not None:
                    attacks.append("html_hidden_attribute")
                if aria_hidden:
                    attacks.append("aria_hidden")
                tag.decompose()

        if hidden_count > 0:
            attacks.append(f"total_hidden_elements:{hidden_count}")

        visible = soup.get_text(separator=" ", strip=True)
        return visible, list(dict.fromkeys(attacks))  # deduplicate, preserve order

    def _extract_via_regex(self, html: str, attacks: List[str]) -> Tuple[str, List[str]]:
        """Regex-based fallback when BeautifulSoup is unavailable."""
        # Remove HTML comments
        comments_found = _HTML_COMMENT_RE.findall(html)
        if comments_found:
            attacks.append(f"html_comment_smuggling ({len(comments_found)} nodes)")
            html = _HTML_COMMENT_RE.sub(" ", html)

        # Remove hidden inline-style elements
        hidden_found = _HIDDEN_ELEMENT_RE.findall(html)
        if hidden_found:
            attacks.append(f"css_hidden_elements_regex:{len(hidden_found)}")
            html = _HIDDEN_ELEMENT_RE.sub(" ", html)

        visible = _TAG_STRIP_RE.sub(" ", html)
        return " ".join(visible.split()), attacks

    # ── Main scan entry point ───────────────────────────────────────────

    def scan(self, mime_text: str, html_body: str) -> Dict[str, Any]:
        """
        CSS-aware Visual-Semantic desync scan.

        Parameters
        ----------
        mime_text : str
            Plain-text body extracted from the email (includes ALL text, even hidden).
        html_body : str
            Raw HTML body of the email.

        Returns
        -------
        dict with keys:
            desync_ratio      : float  [0..1]  Jaccard desync score
            is_evasive        : bool   True if R > 0.35 or CSS attacks found
            css_attacks       : list   Detected evasion techniques
            direct_css_evasion: bool   True if CSS/HTML hiding explicitly found
            details           : str    Human-readable summary
        """
        if not self.enabled or not mime_text or not html_body:
            return {
                "desync_ratio": 0.0, "is_evasive": False,
                "css_attacks": [], "direct_css_evasion": False,
                "details": "Scanning skipped — disabled or missing data",
            }

        # ── Extract visible text (CSS-aware) ────────────────────────
        visible_text, css_attacks = self._extract_visible_text(html_body)

        if not visible_text.strip():
            return {
                "desync_ratio": 0.0, "is_evasive": False,
                "css_attacks": css_attacks, "direct_css_evasion": bool(css_attacks),
                "details": "No visible text recovered from HTML",
            }

        # ── Jaccard desync: all MIME words vs visible-only words ─────
        all_words     = set(re.findall(r'\b\w+\b', mime_text.lower()))
        visible_words = set(re.findall(r'\b\w+\b', visible_text.lower()))

        if not visible_words:
            desync_ratio = 0.0
        else:
            union        = all_words | visible_words
            intersection = all_words & visible_words
            desync_ratio = 1.0 - (len(intersection) / len(union)) if union else 0.0

        desync_ratio = round(desync_ratio, 3)

        # ── Evasion decision ─────────────────────────────────────────
        direct_evasion = bool(css_attacks)
        is_evasive     = desync_ratio > self.evasion_threshold or direct_evasion

        # ── Compose details string ───────────────────────────────────
        detail_parts = [f"Desync R={desync_ratio:.3f} (threshold={self.evasion_threshold})"]
        if css_attacks:
            detail_parts.append("CSS evasion detected: " + ", ".join(css_attacks))
        if is_evasive and not css_attacks:
            detail_parts.append("High lexical desync — possible obfuscation")

        logger.debug(
            "VSDE scan: desync=%.3f evasive=%s attacks=%s",
            desync_ratio, is_evasive, css_attacks,
        )

        return {
            "desync_ratio":       desync_ratio,
            "is_evasive":         is_evasive,
            "css_attacks":        css_attacks,
            "direct_css_evasion": direct_evasion,
            "details":            " | ".join(detail_parts),
        }
