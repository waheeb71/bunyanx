"""
BunyanX NGFW — Unified Inspection Data Contract
================================================
Single source of truth for all inspection context data.

Rules:
  - context.metadata.get("X") is FORBIDDEN in module code.
  - Always use typed fields: context.http.path, context.http.body, etc.
  - metadata dict is kept ONLY for backward compatibility with legacy modules.
  - All new modules MUST use typed fields.

TLS / HTTPS note:
  - For HTTPS traffic, TLS termination happens in transparent_proxy BEFORE
    context is built. The decrypted stream is parsed by HttpRequestParser.
  - context.tls contains metadata about the original TLS session
    (version, SNI, cipher) even after decryption.
  - This allows WAF/DLP to see both the TLS metadata AND the plaintext body.
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


# ─────────────────────────────────────────────────────────────────────────────
# Sub-contexts (optional per traffic type)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HttpInfo:
    """
    HTTP/HTTPS request information — filled by HttpRequestParser.
    Available for both HTTP (plaintext) and HTTPS (after TLS decryption).
    """
    method: str                # "GET", "POST", "PUT", "DELETE", ...
    path: str                  # "/api/users"  (without query string)
    query: str                 # "q=test&page=1" (empty string if none)
    url: str                   # Full URL: "https://example.com/api/users?q=test"
    host: str                  # Host header value: "example.com"
    headers: Dict[str, str]    # {"Content-Type": "application/json", ...}
    body: bytes                # Raw body bytes
    body_text: str             # Decoded body (UTF-8 best-effort, empty if binary)
    content_type: str          # "application/json" (from Content-Type header)
    http_version: str = "HTTP/1.1"  # "HTTP/1.1" or "HTTP/2"

    @classmethod
    def empty(cls, method: str = "UNKNOWN", host: str = "", url: str = "") -> "HttpInfo":
        """Create a minimal HttpInfo when full parsing is not possible."""
        return cls(
            method=method, path="/", query="", url=url,
            host=host, headers={}, body=b"", body_text="",
            content_type="", http_version="HTTP/1.1"
        )


@dataclass
class TlsInfo:
    """
    TLS session metadata — filled during/after TLS handshake.
    Preserved even after decryption so modules can inspect TLS properties.
    """
    sni: Optional[str] = None          # Server Name Indication (hostname)
    version: Optional[str] = None      # "TLSv1.2", "TLSv1.3"
    cipher: Optional[str] = None       # Negotiated cipher suite
    is_decrypted: bool = False          # True if MITM decryption was performed
    bypass_reason: Optional[str] = None  # Why MITM was bypassed (e.g., "banking")


@dataclass
class DnsInfo:
    """DNS query information."""
    query: str                  # Domain being queried: "example.com"
    query_type: str             # "A", "AAAA", "MX", "TXT", "CNAME", ...
    response: Optional[str] = None    # Resolved IP or CNAME
    is_encrypted: bool = False  # DoH / DoT


@dataclass
class SmtpInfo:
    """Email (SMTP) session information."""
    from_addr: str              # MAIL FROM address
    to_addrs: List[str]         # RCPT TO addresses
    subject: Optional[str] = None
    has_attachments: bool = False
    attachment_names: List[str] = field(default_factory=list)


@dataclass
class IdentityContext:
    """User identity (from auth/LDAP enricher)."""
    user_id: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None

    @property
    def username(self) -> Optional[str]:
        """Alias for user_id — UBA and legacy code use 'username'."""
        return self.user_id


@dataclass
class RiskContext:
    """Risk score context (from AI/enrichers)."""
    score: float = 0.0
    tags: List[str] = field(default_factory=list)


@dataclass
class SessionContext:
    """Session context."""
    session_id: Optional[str] = None
    is_authenticated: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Main Inspection Context — the unified data contract
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InspectionContext:
    """
    Unified inspection data contract for BunyanX NGFW.

    Every inspection plugin receives exactly one InspectionContext.
    The proxy builds this context BEFORE calling the inspection pipeline.

    Network fields (src_ip, dst_ip, etc.) are ALWAYS populated.
    Application fields (http, tls, dns, smtp) are populated only when
    the protocol is known and the data has been parsed.

    TLS/HTTPS flow:
      1. TLS handshake → TlsInfo populated (sni, version)
      2. MITM decryption → TlsInfo.is_decrypted = True
      3. HTTP parsing → HttpInfo populated (path, body, headers)
      4. context.protocol set to "HTTPS" (not "TCP")

    Usage in modules:
      if context.http is None:
          return InspectionResult(action=InspectionAction.ALLOW)
      path = context.http.path          # ✅ typed, always set
      body = context.http.body_text     # ✅ decoded body
      sni  = context.tls.sni if context.tls else None
    """

    # ── Network (always populated) ──────────────────────────────────────────
    src_ip: str                         # Client IP
    dst_ip: str                         # Target IP
    src_port: int                       # Client port
    dst_port: int                       # Target port
    protocol: str                       # "TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMTP"
    direction: str                      # "inbound" | "outbound"
    flow_id: str                        # "{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    timestamp: float = field(default_factory=time.time)

    # ── Application layer (optional — depends on protocol) ──────────────────
    http: Optional[HttpInfo] = None     # HTTP/HTTPS request data (after decryption)
    tls: Optional[TlsInfo] = None       # TLS session metadata (for HTTPS)
    dns: Optional[DnsInfo] = None       # DNS query data
    smtp: Optional[SmtpInfo] = None     # SMTP session data

    # ── Tags (added by enrichers/proxy) ────────────────────────────────────
    tags: set = field(default_factory=set)
    # Examples: {"internal", "trusted", "vip", "encrypted", "decrypted"}

    # ── Identity / Risk / Session (from enrichers) ──────────────────────────
    identity: Optional[IdentityContext] = None
    risk: Optional[RiskContext] = None
    session: Optional[SessionContext] = None

    # ── Backward compatibility ───────────────────────────────────────────────
    # DEPRECATED: Use typed fields above. This dict is kept ONLY for legacy
    # modules that still use context.metadata.get("X"). New modules must NOT
    # use this field. It will be removed in a future version.
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.identity is None:
            self.identity = IdentityContext()
        if self.risk is None:
            self.risk = RiskContext()
        if self.session is None:
            self.session = SessionContext()

    # ── Convenience properties ───────────────────────────────────────────────

    @property
    def is_http(self) -> bool:
        """True if this is an HTTP or HTTPS connection with parsed data."""
        return self.http is not None

    @property
    def is_encrypted(self) -> bool:
        """True if the original connection was TLS (even if now decrypted)."""
        return self.tls is not None

    @property
    def is_ssl_inspected(self) -> bool:
        """
        True إذا كانت هذه الحزمة HTTPS وقام محرك MITM بفك تشفيرها.

        استخدم هذا في موديولات الفحص لتعديل السلوك بناءً على سياق الفك:
          - JA3 Fingerprint لا معنى له (بصمة الـ Proxy وليس المتصفح)
          - Bot Score يحتاج تخفيف (الـ Proxy يُعيد بناء Headers)
          - عتبة Deception أعلى (لمنع الحلقة الذاتية القاتلة)

        يُعادل: ctx.tls is not None and ctx.tls.is_decrypted == True
        """
        return self.tls is not None and self.tls.is_decrypted

    @property
    def is_internal(self) -> bool:
        """True if traffic is tagged as internal."""
        return "internal" in self.tags

    @property
    def is_vip(self) -> bool:
        """True if traffic is a VIP-mapped connection."""
        return "vip" in self.tags

    def to_legacy_metadata(self) -> Dict[str, Any]:
        """
        Build a legacy metadata dict from typed fields.
        Used to populate self.metadata for backward-compatible module access.
        Called by ContextBuilder after building the context.
        """
        m: Dict[str, Any] = {}
        if self.http:
            m["request_url"] = self.http.url
            m["url"] = self.http.url
            m["request_path"] = self.http.path
            m["path"] = self.http.path
            m["method"] = self.http.method
            m["query"] = self.http.query
            m["host"] = self.http.host
            m["request_headers"] = self.http.headers
            m["content_type"] = self.http.content_type
            m["body"] = self.http.body
            m["body_text"] = self.http.body_text
        if self.tls:
            m["tls_sni"] = self.tls.sni
            m["tls_version"] = self.tls.version
            m["tls_decrypted"] = self.tls.is_decrypted
        if self.dns:
            m["dns_query"] = self.dns.query
            m["dns_type"] = self.dns.query_type
        if self.smtp:
            m["smtp_from"] = self.smtp.from_addr
            m["smtp_to"] = self.smtp.to_addrs
            m["smtp_subject"] = self.smtp.subject
        m["tags"] = list(self.tags)
        m["proxied"] = True  # backward compat marker
        return m
