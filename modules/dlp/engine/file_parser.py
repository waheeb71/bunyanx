"""
bunyanx NGFW — DLP File Content Extractor
=============================================
Extracts plain text from binary payloads for regex/DLP inspection.

Supported formats (detection is magic-byte based, NOT filename-based):
  - Plain text (UTF-8, Latin-1, ASCII)
  - PDF  (via PyPDF2 / pypdf — optional)
  - DOCX / XLSX / PPTX  (ZIP-based Office Open XML — built-in zipfile)
  - ODT / ODS  (ZIP-based ODF — built-in zipfile)
  - ZIP archives (recursive first-level extraction)
  - RTF (basic text stripping)
  - HTML/XML (tag removal)
  - CSV (plaintext — falls through to UTF-8 decoder)

Design principles
-----------------
* Magic-byte detection first: we NEVER rely solely on filename/extension
  since attackers rename files to evade detection.
* All parsers are wrapped in try/except; a failed parse returns the raw
  bytes decoded as UTF-8 (lossy) so entropy analysis still runs.
* No external network calls. All parsing is local.
* Optional dependencies (PyPDF2/pypdf) degrade gracefully — a WARNING is
  logged once and PDF falls back to raw-byte decoding.
* Max extracted text is capped at MAX_TEXT_BYTES to prevent memory blowup
  from large archives.
"""

import io
import re
import logging
import zipfile
import xml.etree.ElementTree as ET
from typing import Optional

from modules.dlp.config.loader import get_max_extracted_text_bytes

logger = logging.getLogger(__name__)

# Maximum characters extracted per payload (prevents OOM on huge files)
MAX_TEXT_BYTES: int = 2 * 1024 * 1024  # 2 MB of text

# ── Magic byte signatures ─────────────────────────────────────────────────────
_MAGIC_PDF  = b"%PDF"
_MAGIC_ZIP  = b"PK\x03\x04"
_MAGIC_RTF  = b"{\\rtf"
_MAGIC_HTML = (b"<!DOCTYPE", b"<html", b"<HTML")
_MAGIC_XML  = b"<?xml"

# XML namespaces used in OOXML / ODF
_OOXML_NS = {
    "w":  "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "a":  "http://schemas.openxmlformats.org/drawingml/2006/main",
    "v":  "urn:schemas-microsoft-com:vml",
}


# ─── Optional dependency: PyPDF2 / pypdf ─────────────────────────────────────
_PDF_READER = None
_PDF_WARN_SHOWN = False

def _try_import_pdf():
    global _PDF_READER, _PDF_WARN_SHOWN
    if _PDF_READER is not None:
        return _PDF_READER
    try:
        import pypdf  # preferred (pypdf2 successor)
        _PDF_READER = pypdf.PdfReader
        logger.debug("[DLP][PARSER] Using 'pypdf' for PDF extraction.")
        return _PDF_READER
    except ImportError:
        pass
    try:
        from PyPDF2 import PdfReader  # type: ignore
        _PDF_READER = PdfReader
        logger.debug("[DLP][PARSER] Using 'PyPDF2' for PDF extraction.")
        return _PDF_READER
    except ImportError:
        pass
    if not _PDF_WARN_SHOWN:
        logger.warning(
            "[DLP][PARSER] Neither 'pypdf' nor 'PyPDF2' is installed. "
            "PDF files will fall back to raw byte decoding — structured text "
            "within PDFs may NOT be detected. "
            "Install with: pip install pypdf"
        )
        _PDF_WARN_SHOWN = True
    return None


# ─── Core extraction functions ─────────────────────────────────────────────────

def _extract_pdf(data: bytes) -> str:
    """Extract text from a PDF binary. Returns empty string on failure."""
    reader_cls = _try_import_pdf()
    if reader_cls is None:
        return ""
    try:
        reader = reader_cls(io.BytesIO(data))
        parts = []
        for page in reader.pages:
            try:
                parts.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(parts)
    except Exception as e:
        logger.debug("[DLP][PARSER] PDF extraction failed: %s", e)
        return ""


def _extract_ooxml_docx(zf: zipfile.ZipFile) -> str:
    """Extract text from DOCX (word/document.xml)."""
    parts = []
    targets = [
        "word/document.xml",
        "word/header1.xml",
        "word/footer1.xml",
        "word/comments.xml",
    ]
    for target in targets:
        if target not in zf.namelist():
            continue
        try:
            xml_data = zf.read(target)
            root = ET.fromstring(xml_data)
            # Collect all <w:t> text runs
            for elem in root.iter():
                if elem.tag.endswith("}t") and elem.text:
                    parts.append(elem.text)
        except Exception:
            continue
    return " ".join(parts)


def _extract_ooxml_xlsx(zf: zipfile.ZipFile) -> str:
    """Extract text from XLSX (xl/sharedStrings.xml + sheet data)."""
    parts = []
    try:
        if "xl/sharedStrings.xml" in zf.namelist():
            xml_data = zf.read("xl/sharedStrings.xml")
            root = ET.fromstring(xml_data)
            for elem in root.iter():
                if elem.tag.endswith("}t") and elem.text:
                    parts.append(elem.text)
    except Exception:
        pass
    return " ".join(parts)


def _extract_odf(zf: zipfile.ZipFile) -> str:
    """Extract text from ODT/ODS (content.xml)."""
    if "content.xml" not in zf.namelist():
        return ""
    try:
        xml_data = zf.read("content.xml")
        root = ET.fromstring(xml_data)
        texts = []
        for elem in root.iter():
            if elem.text and elem.text.strip():
                texts.append(elem.text.strip())
        return " ".join(texts)
    except Exception as e:
        logger.debug("[DLP][PARSER] ODF extraction failed: %s", e)
        return ""


# Maximum extracted size to prevent ZIP bomb attacks (100 MB)
MAX_ZIP_EXTRACT_SIZE = 100 * 1024 * 1024

def _extract_zip(data: bytes) -> str:
    """
    Extract text from a ZIP archive (first-level files only, non-recursive
    to prevent ZIP-bomb exposure).

    SECURITY FIX (CRITICAL): Added total extraction size limit to prevent
    ZIP bomb DoS attacks. If total decompressed size exceeds MAX_ZIP_EXTRACT_SIZE,
    extraction stops and partial results are returned.

    Handles ZIP-based Office formats (DOCX/XLSX/PPTX/ODT) by detecting
    the internal structure, then delegates to the appropriate extractor.
    Falls back to decoding each member as UTF-8.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return ""
    
    # Track total extracted size to prevent ZIP bomb
    total_extracted_size = 0

    namelist = zf.namelist()

    # Detect OOXML DOCX
    if "word/document.xml" in namelist:
        return _extract_ooxml_docx(zf)

    # Detect OOXML XLSX
    if "xl/workbook.xml" in namelist:
        return _extract_ooxml_xlsx(zf)

    # Detect OOXML PPTX
    if any(n.startswith("ppt/slides/slide") for n in namelist):
        parts = []
        for name in namelist:
            if name.startswith("ppt/slides/slide") and name.endswith(".xml"):
                try:
                    xml_data = zf.read(name)
                    root = ET.fromstring(xml_data)
                    for elem in root.iter():
                        if elem.tag.endswith("}t") and elem.text:
                            parts.append(elem.text)
                except Exception:
                    continue
        return " ".join(parts)

    # Detect ODF (ODT/ODS)
    if "content.xml" in namelist:
        return _extract_odf(zf)

    # Generic ZIP: decode plaintext member files (cap at 10 members)
    # SECURITY FIX: Check total extraction size to prevent ZIP bomb
    parts = []
    for name in namelist[:10]:
        if name.endswith("/"):  # directory entry
            continue
        try:
            member_data = zf.read(name)
            total_extracted_size += len(member_data)
            
            # Check extraction size limit
            if total_extracted_size > MAX_ZIP_EXTRACT_SIZE:
                logger.warning(
                    "[DLP][PARSER] ZIP extraction size limit reached (%d bytes) — "
                    "stopping extraction to prevent ZIP bomb attack",
                    MAX_ZIP_EXTRACT_SIZE
                )
                break
            
            # Skip obviously binary members
            if member_data[:4] in (b"\x00\x00\x00\x00",) or b"\x00" * 8 in member_data[:256]:
                continue
            text = member_data.decode("utf-8", errors="ignore")
            if text.strip():
                parts.append(text)
        except Exception:
            continue
    return "\n".join(parts)


def _strip_html_tags(data: bytes) -> str:
    """Strip HTML/XML tags, return visible text."""
    try:
        text = data.decode("utf-8", errors="ignore")
        # Remove script/style blocks
        text = re.sub(r"<(script|style)[^>]*>.*?</(script|style)>", "", text,
                      flags=re.DOTALL | re.IGNORECASE)
        # Remove all remaining tags
        text = re.sub(r"<[^>]+>", " ", text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text)
        return text.strip()
    except Exception:
        return ""


def _strip_rtf(data: bytes) -> str:
    """Basic RTF plain text extraction (strip control words and groups)."""
    try:
        text = data.decode("latin-1", errors="ignore")
        # Remove RTF groups and control words
        text = re.sub(r"\{[^{}]*\}", " ", text)
        text = re.sub(r"\\[a-z]+\d*\s?", " ", text)
        text = re.sub(r"\\\n", "\n", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()
    except Exception:
        return ""


# ─── Public API ───────────────────────────────────────────────────────────────

class FileParser:
    """
    Extracts plain text from binary payloads for DLP inspection.

    Detection is magic-byte based — filenames are not trusted.
    All parsers degrade gracefully: if structured extraction fails,
    raw UTF-8 decoding is attempted as a last resort so that entropy
    analysis still has data to work with.
    """

    @classmethod
    def extract_text(cls, file_bytes: bytes, filename: str = "") -> str:
        """
        Extract text from *file_bytes* for DLP regex scanning.

        Parameters
        ----------
        file_bytes : raw payload bytes
        filename   : optional hint (used only for logging; NOT for format detection)

        Returns
        -------
        str : extracted plain text, capped at MAX_TEXT_BYTES characters.
              Returns empty string only if every extraction path fails.
        """
        if not file_bytes:
            return ""

        text = cls._extract(file_bytes, filename)

        max_text_bytes = get_max_extracted_text_bytes()
        # Cap to prevent memory blow-up from enormous files
        if len(text) > max_text_bytes:
            logger.debug(
                "[DLP][PARSER] Extracted text truncated to %d bytes (was %d) for %s",
                max_text_bytes, len(text), filename or "<unknown>",
            )
            text = text[:max_text_bytes]

        return text

    @classmethod
    def _extract(cls, data: bytes, filename: str) -> str:
        """Dispatch to the appropriate extractor based on magic bytes."""

        # ── PDF ────────────────────────────────────────────────────────────
        if data[:4] == _MAGIC_PDF:
            result = _extract_pdf(data)
            if result.strip():
                logger.debug("[DLP][PARSER] PDF extraction succeeded for %s", filename)
                return result
            # Fall through to raw decode on empty result
            logger.debug("[DLP][PARSER] PDF extraction empty, falling back to raw for %s", filename)

        # ── ZIP-based formats (DOCX, XLSX, PPTX, ODT, ODS, ZIP) ───────────
        elif data[:4] == _MAGIC_ZIP:
            result = _extract_zip(data)
            if result.strip():
                logger.debug("[DLP][PARSER] ZIP/OOXML/ODF extraction succeeded for %s", filename)
                return result
            logger.debug("[DLP][PARSER] ZIP extraction empty, falling back to raw for %s", filename)

        # ── RTF ────────────────────────────────────────────────────────────
        elif data[:5] == _MAGIC_RTF:
            return _strip_rtf(data)

        # ── HTML / XML ─────────────────────────────────────────────────────
        elif any(data[:len(m)].upper() == m.upper() for m in _MAGIC_HTML) or data[:5] == _MAGIC_XML:
            return _strip_html_tags(data)

        # ── Fallback: raw UTF-8 decode (plain text, CSV, JSON, code, etc.) ─
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            try:
                return data.decode("latin-1", errors="ignore")
            except Exception as e:
                logger.warning(
                    "[DLP][PARSER] All extraction methods failed for %s: %s",
                    filename or "<unknown>", e,
                )
                return ""

    @staticmethod
    def supported_formats() -> list:
        """Return list of supported format descriptions for health/status endpoints."""
        return [
            "plain text (UTF-8, Latin-1)",
            "PDF (requires pypdf or PyPDF2)",
            "DOCX / DOCM (OOXML)",
            "XLSX / XLSM (OOXML)",
            "PPTX / PPTM (OOXML)",
            "ODT / ODS (ODF)",
            "ZIP archives (first-level)",
            "HTML / XML",
            "RTF",
            "CSV / JSON / source code",
        ]
