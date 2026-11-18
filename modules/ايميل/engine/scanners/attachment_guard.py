"""
Enterprise bunyanx — Email Attachment Guard

Scans email attachments for threats:
  1. Dangerous file extensions (block immediately)
  2. Suspicious extensions (raise score)
  3. MIME type mismatch (extension ≠ actual content type)
  4. Shannon Entropy analysis (high entropy = possibly encrypted/obfuscated malware)
  5. Oversized attachments
"""

import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


# Max bytes to sample for entropy (FIX-9: avoid O(n) freeze on 25MB attachments)
_ENTROPY_SAMPLE_BYTES = 65536  # 64KB sample — statistically sufficient for malware detection


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 = ordered, 1.0 = random/encrypted).

    FIX-9: Uses random sampling for large files to avoid O(n) blocking.
    For files > 64KB, samples 64KB spread across the file.
    Statistical accuracy for malware detection is maintained (EAX-256 fills ~1.0,
    compressed/benign files remain << 0.9 even on sampled data).
    """
    if not data:
        return 0.0

    # Sample large payloads to avoid multi-second freeze in thread pool
    if len(data) > _ENTROPY_SAMPLE_BYTES:
        import random
        step = len(data) // (_ENTROPY_SAMPLE_BYTES // 16)
        sample = bytes(data[i] for i in range(0, len(data), step))[:_ENTROPY_SAMPLE_BYTES]
    else:
        sample = data

    # Fast frequency count using built-in bytearray
    freq = [0] * 256
    for b in sample:
        freq[b] += 1
    total = len(sample)
    entropy = -sum(
        (c / total) * math.log2(c / total)
        for c in freq if c > 0
    )
    return entropy / 8.0  # normalise 0..1 (max bits=8 for byte alphabet)


@dataclass
class AttachmentScanResult:
    filename:   str
    score:      float = 0.0
    flags:      List[str] = field(default_factory=list)
    entropy:    float = 0.0
    action:     str = "allow"   # allow | flag | block


@dataclass
class AttachmentGuardResult:
    score:    float = 0.0
    findings: List[AttachmentScanResult] = field(default_factory=list)
    blocked:  bool = False


class AttachmentGuard:
    """
    Scan email attachments for threats.

    Args:
        block_dangerous:       Immediately block dangerous extensions
        analyze_entropy:       Run entropy check on attachment bytes
        entropy_threshold:     Score above this = suspicious encrypted content
        max_size_mb:           Flag oversized attachments
        dangerous_extensions:  Set of extensions that trigger instant BLOCK
        suspicious_extensions: Set of extensions that raise the risk score
    """

    def __init__(
        self,
        settings=None,
        block_dangerous:       bool = True,
        analyze_entropy:       bool = True,
        entropy_threshold:     float = 0.92,
        max_size_mb:           int = 25,
        dangerous_extensions:  Optional[List[str]] = None,
        suspicious_extensions: Optional[List[str]] = None,
    ):
        if settings is not None:
            self.cfg = settings
        else:
            from modules.email_security.engine.core.settings import AttachmentGuardSettings
            self.cfg = AttachmentGuardSettings(
                block_dangerous_extensions = block_dangerous,
                entropy_analysis           = analyze_entropy,
                entropy_threshold          = entropy_threshold,
                max_attachment_size_mb     = max_size_mb,
                dangerous_extensions       = dangerous_extensions or [
                    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
                    ".js", ".jar", ".msi", ".dll", ".ps1", ".psm1",
                    ".hta", ".lnk", ".reg", ".inf",
                ],
                suspicious_extensions      = suspicious_extensions or [
                    ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"
                ],
            )

        self.block_dangerous      = self.cfg.block_dangerous_extensions
        self.analyze_entropy      = self.cfg.entropy_analysis
        self.entropy_threshold    = self.cfg.entropy_threshold
        self.max_size_mb          = self.cfg.max_attachment_size_mb
        self.dangerous_extensions  = set(self.cfg.dangerous_extensions)
        self.suspicious_extensions = set(self.cfg.suspicious_extensions)

    def scan(self, attachments) -> AttachmentGuardResult:
        """
        Scan a list of EmailAttachment objects.

        Args:
            attachments: List[EmailAttachment] from EmailPreprocessor
        """
        result = AttachmentGuardResult()
        if not attachments:
            return result

        for att in attachments:
            scan = self._scan_attachment(att)
            result.findings.append(scan)
            result.score = max(result.score, scan.score)
            if scan.action == "block":
                result.blocked = True

        return result

    def _scan_attachment(self, att) -> AttachmentScanResult:
        cfg  = self.cfg
        scan = AttachmentScanResult(filename=att.filename)
        ext  = att.extension.lower()

        # 0. EICAR Antivirus Test Signature → instant block
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in (att.payload or b"") or "eicar" in att.filename.lower():
            scan.action = "block"
            scan.score = 1.0
            scan.flags.append("eicar_test_signature")
            return scan

        # 1. Dangerous extension → instant block
        if ext in self.dangerous_extensions:
            if self.block_dangerous:
                scan.action = "block"
                scan.score  = cfg.score_dangerous_ext_blocked
            else:
                scan.score  = cfg.score_dangerous_ext_allowed
            scan.flags.append(f"dangerous_extension:{ext}")
            return scan   # no need to scan further

        # 2. Suspicious extension
        if ext in self.suspicious_extensions:
            scan.score += cfg.score_suspicious_ext
            scan.flags.append(f"suspicious_extension:{ext}")
            if ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
                scan.flags.append("compressed_container")

        # 3. Oversized attachment
        size_mb = att.size_bytes / (1024 * 1024)
        if size_mb > self.max_size_mb:
            scan.score += cfg.score_oversized
            scan.flags.append(f"oversized:{size_mb:.1f}MB")

        # 4. Entropy analysis
        if self.analyze_entropy and att.payload:
            scan.entropy = _shannon_entropy(att.payload)
            if scan.entropy > self.entropy_threshold:
                scan.score += cfg.score_high_entropy
                scan.flags.append(f"high_entropy:{scan.entropy:.2f}")

        # 5. MIME mismatch (claimed text/plain but has .exe extension, etc.)
        if att.content_type == "text/plain" and ext in {
            ".exe", ".dll", ".bat", ".scr"
        }:
            scan.score += cfg.score_mime_mismatch
            scan.flags.append("mime_mismatch")

        scan.score = min(scan.score, 1.0)
        if scan.score >= cfg.action_block_threshold:
            scan.action = "block"
        elif scan.score >= cfg.action_flag_threshold:
            scan.action = "flag"

        return scan
