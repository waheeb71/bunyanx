"""
BunyanX NGFW — HTTP Request Parser
====================================
Converts raw HTTP/HTTPS bytes (after TLS decryption) into a typed HttpInfo.

Design:
  - Handles HTTP/1.0, HTTP/1.1 (keep-alive streams)
  - Does NOT handle HTTP/2 binary frames (future: h2 library)
  - Called by ContextBuilder AFTER TLS decryption has occurred
  - Body is read up to MAX_BODY_BYTES to avoid memory exhaustion
  - All errors are caught — returns None on parse failure

Usage:
    parser = HttpRequestParser(max_body_bytes=1_048_576)
    http_info = parser.parse_from_bytes(raw_bytes)
    if http_info:
        context.http = http_info
"""

import logging
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from system.core.inspection_context import HttpInfo

logger = logging.getLogger(__name__)

# Maximum body size we'll store in context (32 MB for full malware/AV/DLP inspection)
MAX_BODY_BYTES = 33_554_432

# Maximum header section size (64 KB)
MAX_HEADER_BYTES = 65_536


class HttpRequestParser:
    """
    Parses raw HTTP/1.x request bytes into a typed HttpInfo object.

    Thread-safe: stateless, can be shared across connections.

    TLS/HTTPS note:
      This parser operates on PLAINTEXT bytes. For HTTPS traffic, the
      TLS layer in transparent_proxy._perform_mitm() decrypts the stream
      BEFORE this parser is called. The parser is protocol-agnostic:
      it does not know (or care) whether the original connection was HTTP
      or HTTPS — that distinction is captured in TlsInfo.
    """

    def __init__(self, max_body_bytes: int = MAX_BODY_BYTES):
        self.max_body_bytes = max_body_bytes

    def parse_from_bytes(self, raw: bytes, scheme: str = "http") -> Optional[HttpInfo]:
        """
        Parse raw HTTP request bytes into HttpInfo.

        Args:
            raw: Raw bytes read from the (possibly decrypted) stream.
                 Should include the request line + headers + body.
            scheme: "http" or "https" (from TlsInfo, set by proxy layer)

        Returns:
            HttpInfo on success, None if parsing fails.
        """
        if not raw:
            return None

        try:
            # Split headers section from body
            # HTTP spec: headers end at first \r\n\r\n or \n\n
            sep = raw.find(b"\r\n\r\n")
            if sep == -1:
                sep = raw.find(b"\n\n")
                if sep == -1:
                    # Only headers, no body
                    header_bytes = raw
                    body = b""
                else:
                    header_bytes = raw[:sep]
                    body = raw[sep + 2:]
            else:
                header_bytes = raw[:sep]
                body = raw[sep + 4:]

            # Limit header section size
            if len(header_bytes) > MAX_HEADER_BYTES:
                logger.warning("[HttpParser] Header section too large (%d bytes), truncating", len(header_bytes))
                header_bytes = header_bytes[:MAX_HEADER_BYTES]

            # Decode headers (latin-1 is the safe default for HTTP headers)
            header_text = header_bytes.decode("latin-1", errors="replace")
            lines = header_text.split("\r\n") if "\r\n" in header_text else header_text.split("\n")

            if not lines:
                return None

            # --- Parse request line ---
            method, path, query, url, http_version = self._parse_request_line(lines[0], scheme)
            if not method:
                return None

            # --- Parse headers ---
            headers, host, content_type = self._parse_headers(lines[1:])

            # Use Host header to build full URL if not already set
            if host and not url.startswith("http"):
                url = f"{scheme}://{host}{path}"
                if query:
                    url += f"?{query}"

            # --- Truncate body if too large ---
            if len(body) > self.max_body_bytes:
                logger.debug("[HttpParser] Body truncated from %d to %d bytes", len(body), self.max_body_bytes)
                body = body[:self.max_body_bytes]

            # --- Decode body text ---
            body_text = self._decode_body(body, content_type)

            return HttpInfo(
                method=method,
                path=path,
                query=query,
                url=url,
                host=host,
                headers=headers,
                body=body,
                body_text=body_text,
                content_type=content_type,
                http_version=http_version,
            )

        except Exception as exc:
            logger.debug("[HttpParser] Parse failed: %s", exc)
            return None

    def parse_from_first_line_and_headers(
        self,
        first_line: bytes,
        headers_raw: bytes,
        scheme: str = "http",
    ) -> Optional[HttpInfo]:
        """
        Parse from already-split first line + headers (no body available yet).
        Used when the proxy reads headers line-by-line before body.

        Body will be b"" — caller should update context.http.body separately
        if/when body becomes available.
        """
        try:
            raw = first_line + headers_raw + b"\r\n"
            return self.parse_from_bytes(raw, scheme=scheme)
        except Exception as exc:
            logger.debug("[HttpParser] parse_from_first_line failed: %s", exc)
            return None

    # ── Private helpers ──────────────────────────────────────────────────────

    def _parse_request_line(
        self, line: str, scheme: str
    ) -> Tuple[str, str, str, str, str]:
        """
        Parse HTTP request line: "METHOD URL HTTP/1.1"

        Returns:
            (method, path, query, full_url, http_version)
            On failure returns ("", "", "", "", "")
        """
        try:
            parts = line.strip().split(" ", 2)
            if len(parts) < 2:
                return ("", "", "", "", "")

            method = parts[0].upper()
            raw_url = parts[1]
            http_version = parts[2].strip() if len(parts) > 2 else "HTTP/1.0"

            # Validate method
            valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                             "OPTIONS", "TRACE", "CONNECT"}
            if method not in valid_methods:
                logger.debug("[HttpParser] Unknown HTTP method: %s", method)
                # Don't fail — WAF should see it too

            # Parse URL
            if raw_url.startswith("http://") or raw_url.startswith("https://"):
                parsed = urlparse(raw_url)
                path = parsed.path or "/"
                query = parsed.query or ""
                url = raw_url
            elif raw_url.startswith("/"):
                path = raw_url.split("?")[0]
                query = raw_url.split("?")[1] if "?" in raw_url else ""
                url = ""  # Will be filled from Host header later
            elif raw_url == "*":
                # OPTIONS * HTTP/1.1
                path = "*"
                query = ""
                url = ""
            else:
                path = raw_url
                query = ""
                url = ""

            return (method, path, query, url, http_version)

        except Exception as exc:
            logger.debug("[HttpParser] Request line parse error: %s | line=%r", exc, line)
            return ("", "", "", "", "")

    def _parse_headers(
        self, lines: list
    ) -> Tuple[Dict[str, str], str, str]:
        """
        Parse HTTP headers from list of lines.

        Returns:
            (headers_dict, host, content_type)
        """
        headers: Dict[str, str] = {}
        host = ""
        content_type = ""

        for line in lines:
            line = line.strip()
            if not line:
                break
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            # Normalize header names to lowercase for consistent access
            key_lower = key.lower()
            headers[key_lower] = value

            if key_lower == "host":
                # Strip port from host if present
                host = value.split(":")[0] if ":" in value else value
            elif key_lower == "content-type":
                # Extract MIME type without charset
                content_type = value.split(";")[0].strip()

        return headers, host, content_type

    def _decode_body(self, body: bytes, content_type: str) -> str:
        """
        Attempt to decode body bytes to text.
        Returns empty string for binary content (images, archives, etc.).
        """
        if not body:
            return ""

        # Skip decoding for known binary types
        binary_types = {
            "application/octet-stream", "image/", "video/", "audio/",
            "application/zip", "application/gzip", "application/pdf",
            "application/x-www-form-urlencoded",  # decode these below
        }
        ct_lower = content_type.lower()
        for bt in binary_types:
            if ct_lower.startswith(bt) and bt != "application/x-www-form-urlencoded":
                return ""  # Binary — don't decode

        # Try UTF-8 first, then latin-1 fallback
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return body.decode("latin-1", errors="replace")
            except Exception:
                return ""
