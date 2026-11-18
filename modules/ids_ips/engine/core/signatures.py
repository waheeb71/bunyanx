"""
IPS Signatures Engine — Enhanced Snort-Compatible Parser
=========================================================
Supports a rich subset of Snort 3 rule syntax including:
  - Literal content matching  (content:"foo";)
  - Hex-encoded content       (content:"|90 90 90|";)
  - PCRE patterns             (pcre:"/UNION\\s+SELECT/i";)
  - Case-insensitive flag     (nocase;)
  - Positional modifiers      (distance:N; within:N; offset:N; depth:N;)
  - Multi-pattern Aho-Corasick matching for high throughput
  - DB loading from IPSSignature ORM models

Architecture
------------
  SignatureEngine          — public API (load / scan)
  └── _RuleParser          — stateless Snort rule → Signature
  └── _AhoCorasickIndex    — compiled multi-pattern byte index
  └── Signature            — immutable rule representation
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, NamedTuple, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try to import Aho-Corasick (optional — graceful fallback to linear scan)
# ---------------------------------------------------------------------------
try:
   
    import ahocorasick

    _AHO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AHO_AVAILABLE = False
    logger.warning(
        "pyahocorasick not installed — signature matching falls back to "
        "O(n·m) linear scan.  Install with: pip install pyahocorasick"
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContentMatcher:
    """Represents a single content match directive within a rule."""

    raw: bytes          # The literal bytes to search for (after hex decode)
    nocase: bool = False
    offset: int = 0     # Start searching from this byte position
    depth: int = 0      # Search at most this many bytes (0 = no limit)
    distance: int = -1  # Bytes after last match end (-1 = not set)
    within: int = 0     # Max bytes after distance start (0 = no limit)
    is_pcre: bool = False
    pcre_pattern: Optional[re.Pattern] = field(default=None, compare=False, hash=False)


@dataclass
class Signature:
    """Parsed Snort rule — immutable after construction."""

    sid: int
    msg: str
    action: str               # alert / drop / pass / log
    protocol: str             # tcp / udp / http / any / …
    src_ip: str
    src_port: str
    direction: str            # -> / <>
    dst_ip: str
    dst_port: str
    matchers: List[ContentMatcher] = field(default_factory=list)
    raw_rule: str = ""        # original rule string (for debugging)

    # Optional metadata
    classtype: str = ""
    priority: int = 2
    rev: int = 1


# ---------------------------------------------------------------------------
# Aho-Corasick index (built from literal matchers, case-folded if nocase)
# ---------------------------------------------------------------------------

class _AhoCorasickIndex:
    """
    Wraps an Aho-Corasick automaton for O(n) multi-pattern search.

    The automaton maps each byte pattern to the list of SIDs that contain it.
    PCRE matchers are NOT added here — they are evaluated separately.
    """

    def __init__(self) -> None:
        self._automaton: Optional[ahocorasick.Automaton] = None if _AHO_AVAILABLE else None
        # pattern_bytes → {sid, ...}
        self._pattern_sids: Dict[bytes, set] = {}

    def build(self, sigs: List[Signature]) -> None:
        """Compile the automaton from *sigs*."""
        if not _AHO_AVAILABLE:
            return

        A = ahocorasick.Automaton()
        idx = 0
        for sig in sigs:
            for m in sig.matchers:
                if m.is_pcre:
                    continue  # PCRE handled separately
                pattern = m.raw.lower() if m.nocase else m.raw
                if pattern not in self._pattern_sids:
                    self._pattern_sids[pattern] = set()
                    # pyahocorasick requires a str key — use hex representation
                    key_str = pattern.hex()
                    A.add_word(key_str, (idx, pattern))
                    idx += 1
                self._pattern_sids[pattern].add(sig.sid)

        if idx > 0:
            A.make_automaton()
            self._automaton = A
        else:
            self._automaton = None

    def search(self, data: bytes) -> set:
        """Return set of SIDs whose literal patterns were found in *data*."""
        if not _AHO_AVAILABLE or self._automaton is None:
            return set()

        # We search using the hex representation of the data so that
        # the string-based automaton can find the hex-keyed patterns.
        # data_lower for nocase patterns; the pattern was already lowercased
        # when added to the automaton, so we lowercase the data too.
        data_lower_hex = data.lower().hex()
        found: set = set()
        for _, (_, pattern) in self._automaton.iter(data_lower_hex):
            found.update(self._pattern_sids.get(pattern, set()))
        return found


# ---------------------------------------------------------------------------
# Snort Rule Parser (stateless)
# ---------------------------------------------------------------------------

class _RuleParser:
    """
    Parses a single Snort 3-compatible rule string into a Signature.

    Grammar (simplified):
        <action> <proto> <src_ip> <src_port> <dir> <dst_ip> <dst_port>
        ( <option>; <option>; ... )

    Supported options
    -----------------
        msg:"..."                 — human-readable message
        content:"..."             — literal or hex-encoded bytes
        content:"|HH HH ...|"    — hex-encoded bytes shorthand
        pcre:"/pattern/flags"    — PCRE regular expression
        nocase;                  — case-insensitive (applies to prev. content)
        offset:N;                — search starts at byte N
        depth:N;                 — search at most N bytes
        distance:N;              — relative to previous match
        within:N;                — combined with distance
        sid:N;                   — unique rule ID
        rev:N;                   — rule revision
        classtype:...            — classification label
        priority:N;              — rule priority 1-4
    """

    # ── Regex patterns used during option parsing ──────────────────────────
    _RE_HEADER = re.compile(
        r"^(\w+)\s+"             # action
        r"(\w+)\s+"             # protocol
        r"([\S]+)\s+"           # src_ip
        r"([\S]+)\s+"           # src_port
        r"(<>|->)\s+"           # direction
        r"([\S]+)\s+"           # dst_ip
        r"([\S]+)\s*"           # dst_port
    )

    _RE_HEX_BLOCK = re.compile(r"\|([0-9a-fA-F\s]+)\|")
    _RE_PCRE      = re.compile(r"^/(.+)/([imsx]*)$")

    # ── Public entry point ─────────────────────────────────────────────────
    @classmethod
    def parse(cls, rule_str: str) -> Optional[Signature]:
        """
        Parse *rule_str* into a Signature.

        Returns None and logs a warning on parse failure.
        """
        rule_str = rule_str.strip()
        if not rule_str or rule_str.startswith("#"):
            return None

        # Split header from options block
        paren_open = rule_str.find("(")
        if paren_open == -1:
            logger.warning("Rule has no options block: %.60s", rule_str)
            return None

        header_str  = rule_str[:paren_open].strip()
        options_str = rule_str[paren_open + 1:].rstrip(")")

        # Parse header
        m = cls._RE_HEADER.match(header_str)
        if not m:
            logger.warning("Cannot parse rule header: %.60s", header_str)
            return None

        action, proto, src_ip, src_port, direction, dst_ip, dst_port = m.groups()

        # Parse options into a raw dict & ordered list
        opts, opt_sequence = cls._parse_options(options_str)

        sid = int(opts.get("sid", 0))
        if sid == 0:
            logger.warning("Rule has no SID: %.60s", rule_str)
            return None

        # Build ordered list of ContentMatcher objects
        matchers = cls._build_matchers(opt_sequence)

        return Signature(
            sid       = sid,
            msg       = opts.get("msg", ""),
            action    = action,
            protocol  = proto,
            src_ip    = src_ip,
            src_port  = src_port,
            direction = direction,
            dst_ip    = dst_ip,
            dst_port  = dst_port,
            matchers  = matchers,
            raw_rule  = rule_str,
            classtype = opts.get("classtype", ""),
            priority  = int(opts.get("priority", 2)),
            rev       = int(opts.get("rev", 1)),
        )

    # ── Option tokeniser ───────────────────────────────────────────────────
    @classmethod
    def _parse_options(cls, options_str: str) -> Tuple[Dict[str, str], list]:
        """
        Tokenise the options block, respecting quoted strings.

        Returns
        -------
        opts         — flat key→value dict (last occurrence wins)
        opt_sequence — ordered list of (key, value) for positional modifiers
        """
        opts: Dict[str, str] = {}
        sequence: list = []

        # State machine tokeniser that handles semicolons inside quotes
        tokens: List[str] = []
        current = []
        in_quote = False
        quote_char = ""

        for ch in options_str:
            if in_quote:
                current.append(ch)
                if ch == quote_char:
                    in_quote = False
            elif ch in ('"', "'"):
                in_quote = True
                quote_char = ch
                current.append(ch)
            elif ch == ";":
                token = "".join(current).strip()
                if token:
                    tokens.append(token)
                current = []
            else:
                current.append(ch)

        if current:
            last = "".join(current).strip()
            if last:
                tokens.append(last)

        for token in tokens:
            if ":" in token:
                key, _, val = token.partition(":")
                key = key.strip()
                val = val.strip().strip('"')
                opts[key] = val
                sequence.append((key, val))
            else:
                key = token.strip()
                opts[key] = ""
                sequence.append((key, ""))

        return opts, sequence

    # ── ContentMatcher builder ─────────────────────────────────────────────
    @classmethod
    def _build_matchers(cls, sequence: list) -> List[ContentMatcher]:
        """
        Walk the option sequence and build ordered ContentMatcher objects.

        Positional modifiers (nocase, offset, depth, distance, within)
        are applied to the *most recently defined* content/pcre directive.
        """
        matchers: List[ContentMatcher] = []
        # We build a mutable dict for the current matcher, then freeze it
        pending: Optional[dict] = None

        def _flush():
            nonlocal pending
            if pending is None:
                return
            matchers.append(ContentMatcher(**pending))
            pending = None

        for key, val in sequence:
            if key == "content":
                _flush()
                raw_bytes = cls._decode_content(val)
                pending = {
                    "raw": raw_bytes,
                    "nocase": False,
                    "offset": 0,
                    "depth": 0,
                    "distance": -1,
                    "within": 0,
                    "is_pcre": False,
                    "pcre_pattern": None,
                }

            elif key == "pcre":
                _flush()
                compiled, pattern_bytes = cls._compile_pcre(val)
                pending = {
                    "raw": pattern_bytes,
                    "nocase": False,
                    "offset": 0,
                    "depth": 0,
                    "distance": -1,
                    "within": 0,
                    "is_pcre": True,
                    "pcre_pattern": compiled,
                }

            elif pending is not None:
                # Modifiers applied to current pending matcher
                if key == "nocase":
                    pending["nocase"] = True
                elif key == "offset":
                    pending["offset"] = int(val) if val.isdigit() else 0
                elif key == "depth":
                    pending["depth"] = int(val) if val.isdigit() else 0
                elif key == "distance":
                    pending["distance"] = int(val) if val.lstrip("-").isdigit() else -1
                elif key == "within":
                    pending["within"] = int(val) if val.isdigit() else 0

        _flush()
        return matchers

    # ── Content value decoders ─────────────────────────────────────────────
    @classmethod
    def _decode_content(cls, val: str) -> bytes:
        """
        Decode a content value that may contain hex blocks.

        Examples
        --------
            "UNION SELECT"         → b"UNION SELECT"
            "|90 90 90|"           → b"\\x90\\x90\\x90"
            "HEAD|0d 0a|"          → b"HEAD\\r\\n"
        """
        result = bytearray()
        pos = 0
        while pos < len(val):
            pipe_start = val.find("|", pos)
            if pipe_start == -1:
                result.extend(val[pos:].encode("latin-1", errors="replace"))
                break
            # Add literal text before the pipe
            result.extend(val[pos:pipe_start].encode("latin-1", errors="replace"))
            pipe_end = val.find("|", pipe_start + 1)
            if pipe_end == -1:
                # Unclosed hex block — treat rest as literal
                result.extend(val[pipe_start:].encode("latin-1", errors="replace"))
                break
            hex_str = val[pipe_start + 1 : pipe_end]
            try:
                result.extend(bytes.fromhex(hex_str.replace(" ", "")))
            except ValueError:
                logger.warning("Invalid hex in content: |%s|", hex_str)
                result.extend(f"|{hex_str}|".encode("latin-1"))
            pos = pipe_end + 1
        return bytes(result)

    @classmethod
    def _compile_pcre(cls, val: str) -> Tuple[Optional[re.Pattern], bytes]:
        """
        Compile a pcre:"/.../flags" value.

        Returns (compiled_pattern, raw_pattern_as_bytes)
        """
        m = cls._RE_PCRE.match(val)
        if not m:
            logger.warning("Cannot parse PCRE: %.60s", val)
            return None, val.encode("latin-1", errors="replace")

        pattern_str, flags_str = m.group(1), m.group(2)
        flags = 0
        if "i" in flags_str:
            flags |= re.IGNORECASE
        if "m" in flags_str:
            flags |= re.MULTILINE
        if "s" in flags_str:
            flags |= re.DOTALL
        if "x" in flags_str:
            flags |= re.VERBOSE

        try:
            compiled = re.compile(pattern_str.encode("latin-1", errors="replace"), flags)
        except re.error as exc:
            logger.warning("PCRE compile error (%s): %s", exc, pattern_str[:60])
            compiled = None

        return compiled, pattern_str.encode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# SignatureEngine — public API
# ---------------------------------------------------------------------------

class SignatureEngine:
    """
    Snort-compatible signature engine with Aho-Corasick acceleration.

    Usage
    -----
        engine = SignatureEngine()
        engine.load_defaults()
        alerts = engine.scan(payload_bytes, protocol="tcp")
    """

    def __init__(self) -> None:
        self.signatures: Dict[int, Signature] = {}   # sid → Signature
        self._aho: _AhoCorasickIndex = _AhoCorasickIndex()
        self._aho_dirty: bool = True                 # rebuild needed?
        self._parser = _RuleParser()

    # ── Loading ────────────────────────────────────────────────────────────

    def load_defaults(self) -> None:
        """Load a comprehensive built-in rule set covering OWASP Top 10."""
        defaults = [
            # ── SQL Injection ────────────────────────────────────────────────
            'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS '
            '(msg:"SQL Injection UNION SELECT"; content:"UNION"; nocase; '
            'pcre:"/UNION[\\s+%20]+SELECT/i"; sid:1001; rev:4;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection OR 1=1"; content:"OR"; nocase; '
            'pcre:"/(?:OR|AND)[\\s+%20]+[\\x27\\x221]?[\\s+%20]*[=<>]/i"; sid:1010; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection -- comment"; content:"--"; '
            'pcre:"/(?:[\\x27\\x22\\)\\d]|UNION|SELECT|WHERE|AND|OR|HAVING)[\\s+%20]*-{2,}[\\s+%20]*(?:$|\\r)/i"; sid:1011; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection quote bypass"; '
            r'pcre:"/[\'%27][\\s]*(?:OR|AND|UNION|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|EXEC|SLEEP|BENCHMARK|WAITFOR)/i";'
            ' sid:1012; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection stacked query semicolon"; '
            r'pcre:"/;[\s]*(?:SELECT\s+(?:\*|\w+)|INSERT\s+INTO|UPDATE\s+\w+|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE)|CREATE\s+(?:TABLE|DATABASE)|ALTER\s+TABLE|EXEC(?:UTE)?\s+\w+|DECLARE\s+@)/i"; '
            'sid:1013; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection error-based MSSQL"; '
            'content:"CONVERT("; nocase; pcre:"/CONVERT\\s*\\([^)]*INT[^)]*,/i"; sid:1014; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection SLEEP/BENCHMARK time-based"; '
            'pcre:"/(?:SLEEP\\s*\\(|BENCHMARK\\s*\\(|WAITFOR\\s+DELAY)/i"; sid:1015; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection blind boolean"; '
            'pcre:"/(?:AND|OR)[\\s+%20]+[0-9]+[\\s+%20]*(?:=|LIKE|IS)[\\s+%20]*[0-9]+/i"; sid:1016; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SQL Injection XPath"; '
            'pcre:"/[\'%27][\\s]*or[\\s]*[\'%27]|[\\x27][\\s]*or[\\s]*[\\x27]/i"; sid:1017; rev:2;)',

            # ── XSS (Cross-Site Scripting) ───────────────────────────────────
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"XSS script tag"; '
            'pcre:"/<\\s*script[\\s>]/i"; sid:1020; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"XSS onerror event handler"; '
            'pcre:"/on(?:error|load|click|mouseover|focus|blur|change|submit|keydown|keyup)\\s*=/i"; '
            'sid:1021; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"XSS SVG onload"; '
            'content:"svg"; nocase; pcre:"/<\\s*svg[^>]*onload/i"; sid:1022; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"XSS javascript URI"; '
            'pcre:"/javascript[\\s%09%0a%0d]*:/i"; sid:1023; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"XSS data URI base64"; '
            'pcre:"/data:[^;]*;base64/i"; sid:1024; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"XSS HTML entity bypass"; '
            'pcre:"/&#[xX]?[0-9a-fA-F]+;/"; sid:1025; rev:2;)',

            # ── Path Traversal / LFI ─────────────────────────────────────────
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Path Traversal ../"; content:"../"; nocase; sid:1002; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Path Traversal URL-encoded %2e%2e"; '
            'pcre:"/(?:%2e%2e|%252e%252e|%c0%af|%c1%9c)/i"; sid:1031; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"LFI /etc/passwd"; '
            'content:"etc/passwd"; nocase; sid:1032; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"LFI Windows win.ini"; '
            'content:"win.ini"; nocase; sid:1033; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"LFI PHP filter wrapper"; '
            'content:"php://filter"; nocase; sid:1034; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"LFI PHP input wrapper"; '
            'content:"php://input"; nocase; sid:1035; rev:2;)',

            # ── Command Injection / RCE ──────────────────────────────────────
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Shellshock bash function injection"; '
            'content:"() {"; sid:1040; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Command injection semicolon"; '
            'pcre:"/[;&|`]\\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|python|perl|nc|ncat|netcat)(?:\\s|$)/i"; '
            'sid:1041; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Command injection dollar-paren subshell"; '
            'content:"$("; sid:1042; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Log4Shell JNDI injection"; '
            'content:"|24 7b 6a 6e 64 69 3a|"; nocase; sid:1043; rev:4;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Log4Shell lookup variants"; '
            'pcre:"/\\$\\{(?:lower|upper|:[-:])[^}]*jndi/i"; sid:1044; rev:2;)',

            # ── Scanner / Recon Fingerprinting ───────────────────────────────
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Scanner: sqlmap User-Agent"; '
            'content:"sqlmap"; nocase; sid:1050; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Scanner: Nikto"; '
            'content:"Nikto"; nocase; sid:1051; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Scanner: Nmap scripting engine"; '
            'content:"Nmap Scripting Engine"; nocase; sid:1052; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Scanner: Havij"; '
            'content:"Havij"; nocase; sid:1053; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Scanner: curl/wget recon"; '
            'pcre:"/^User-Agent: (?:curl|Wget|libwww-perl)\\//i"; sid:1054; rev:2;)',

            # ── HTTP Protocol Abuse / SSRF ───────────────────────────────────
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"SSRF localhost access"; '
            r'pcre:"/(?:url|dest|target|redirect|uri|fetch|endpoint|host)=\s*https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)/i"; sid:1060; rev:3;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"HTTP CRLF injection URL-encoded"; '
            'pcre:"/^(?:GET|POST|PUT|HEAD|DELETE|OPTIONS)\\s+[^\\s\\r\\n]*(?:%0[dD]%0[aA]|%0[aA]%0[dD])/i"; sid:1061; rev:4;)',

            # ── Sensitive path enumeration ───────────────────────────────────
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Recon: wp-login access"; '
            'content:"wp-login.php"; nocase; sid:1070; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Recon: phpMyAdmin access"; '
            'content:"phpmyadmin"; nocase; sid:1071; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Recon: Spring actuator env"; '
            'content:"/actuator/env"; nocase; sid:1072; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Recon: .env file access"; '
            'content:"/.env"; nocase; sid:1073; rev:2;)',

            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Recon: .git config access"; '
            'content:"/.git/config"; nocase; sid:1074; rev:2;)',

            # ── Low-level exploits ───────────────────────────────────────────
            # Malformed Host header
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any '
            '(msg:"Malformed Host header (user@host injection)"; '
            'pcre:"/Host:\\s*[^@\\r\\n]+@[^@\\r\\n]+/i"; sid:1062; rev:1;)',

            # SSH Version Scan
            'alert tcp any any -> any 22 '
            '(msg:"SSH Version String Probe"; content:"SSH-2.0-"; nocase; sid:1003; rev:1;)',

            # NOP Sled (shellcode)
            'alert tcp any any -> any any '
            '(msg:"Possible NOP Sled Shellcode"; content:"|90 90 90 90 90 90 90 90|"; '
            'sid:1004; rev:2;)',

            # Metasploit User-Agent shellcode
            'alert tcp any any -> any any '
            '(msg:"Shellcode in User-Agent header"; content:"|90 90 90 90 cc cc cc cc|"; '
            'sid:1007; rev:1;)',

            # Heartbleed TLS heartbeat overflow
            'alert tcp any any -> any any '
            '(msg:"Heartbleed TLS heartbeat overflow"; content:"|18 03 02 00 03 01 40 00|"; '
            'sid:1008; rev:1;)',

            # C2 binary beacon pattern
            'alert tcp any any -> any any '
            '(msg:"C2 binary beacon pattern"; content:"|de ad be ef|"; '
            'sid:1009; rev:1;)',

            # Mimikatz sekurlsa
            'alert tcp any any -> $HOME_NET any '
            '(msg:"Mimikatz sekurlsa pattern"; '
            'content:"|73 65 6b 75 72 6c 73 61|"; sid:1005; rev:1;)',

            # Metasploit Meterpreter HTTPS reverse shell
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"Possible Meterpreter Reverse HTTPS"; '
            'content:"MSSL"; nocase; distance:0; within:64; sid:1006; rev:1;)',
        ]
        for rule in defaults:
            self.add_rule(rule)

    def load_from_db(self, db_signatures: list) -> None:
        """Clear current rules and (re)load from ORM IPSSignature list."""
        self.signatures.clear()
        self._aho_dirty = True
        for db_sig in db_signatures:
            self.add_rule(db_sig.raw_rule)

    def load_rules_file(self, file_path: str) -> int:
        """
        Load rules from a .rules file (one rule per line, # for comments).

        Returns the number of successfully loaded rules.
        """
        loaded = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if self.add_rule(line):
                        loaded += 1
            logger.info("Loaded %d signatures from %s", loaded, file_path)
        except FileNotFoundError:
            logger.warning("Rules file not found: %s", file_path)
        return loaded

    def add_rule(self, rule_str: str) -> bool:
        """
        Parse and add a single rule string.

        Returns True on success, False on parse failure.
        """
        sig = _RuleParser.parse(rule_str)
        if sig is None:
            return False
        if sig.sid in self.signatures:
            logger.debug("Replacing existing rule SID=%d", sig.sid)
        self.signatures[sig.sid] = sig
        self._aho_dirty = True
        return True

    # ── Scanning ───────────────────────────────────────────────────────────

    def scan(
        self,
        payload: bytes,
        protocol: str = "any",
        src_ip: str = "any",
        dst_ip: str = "any",
        dst_port: int = 0,
    ) -> List[str]:
        """
        Scan *payload* against all loaded signatures.

        Parameters
        ----------
        payload  : bytes — raw packet or flow payload
        protocol : str   — "tcp", "udp", "http", … (used for rule filtering)

        Returns
        -------
        List of alert strings for every matched rule, e.g.:
            ["[1004] Possible NOP Sled Shellcode", ...]
        """
        if not payload or not self.signatures:
            return []

        # Rebuild Aho-Corasick automaton if rules have changed
        if self._aho_dirty:
            self._aho.build(list(self.signatures.values()))
            self._aho_dirty = False

        alerts: List[str] = []

        if _AHO_AVAILABLE:
            # Phase 1: fast Aho-Corasick literal pre-filter
            candidate_sids = self._aho.search(payload)

            # Phase 2: detailed check (PCRE, positional modifiers) for candidates
            for sid in candidate_sids:
                sig = self.signatures.get(sid)
                if sig and self._rule_matches(sig, payload, protocol):
                    alerts.append(f"[{sig.sid}] {sig.msg}")

            # Phase 3: pure-PCRE rules not indexed by Aho-Corasick
            for sig in self.signatures.values():
                if sig.sid in candidate_sids:
                    continue  # already checked
                if all(m.is_pcre for m in sig.matchers):
                    if self._rule_matches(sig, payload, protocol):
                        alerts.append(f"[{sig.sid}] {sig.msg}")
        else:
            # Fallback: linear scan without Aho-Corasick
            for sig in self.signatures.values():
                if self._rule_matches(sig, payload, protocol):
                    alerts.append(f"[{sig.sid}] {sig.msg}")

        return alerts

    # ── Matching logic ─────────────────────────────────────────────────────

    @staticmethod
    def _rule_matches(
        sig: Signature, payload: bytes, protocol: str
    ) -> bool:
        """
        Return True if *payload* satisfies ALL matchers in *sig*.

        A rule with no matchers is considered a protocol-level alert
        and always matches (rare but valid in Snort).
        """
        # Protocol filter
        sig_proto = (sig.protocol or "any").lower()
        req_proto = (protocol or "any").lower()

        if sig_proto != "any" and req_proto != "any":
            if sig_proto == "http" and req_proto in ("tcp", "http"):
                pass  # HTTP rules apply to TCP/HTTP flows
            elif sig_proto != req_proto:
                return False

        if not sig.matchers:
            return True

        last_match_end = 0  # tracks end position of last match (for distance)

        for matcher in sig.matchers:
            if matcher.is_pcre:
                if matcher.pcre_pattern is None:
                    continue  # broken PCRE — skip gracefully
                region = payload
                if matcher.offset:
                    region = payload[matcher.offset:]
                m = matcher.pcre_pattern.search(region)
                if m is None:
                    return False
                last_match_end = matcher.offset + m.end()

            else:
                # Literal byte match with positional constraints
                needle = matcher.raw
                if matcher.nocase:
                    hay   = payload.lower()
                    needle = needle.lower()
                else:
                    hay = payload

                # Determine search window
                start = max(matcher.offset, 0)
                if matcher.distance >= 0:
                    start = max(start, last_match_end + matcher.distance)

                end = len(hay)
                if matcher.depth and matcher.offset:
                    end = min(end, matcher.offset + matcher.depth)
                if matcher.within and matcher.distance >= 0:
                    end = min(end, start + matcher.within)

                idx = hay.find(needle, start, end)
                if idx == -1:
                    return False
                last_match_end = idx + len(needle)

        return True

    # ── Info ───────────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self.signatures)

    def stats(self) -> dict:
        pcre_count = sum(
            1
            for sig in self.signatures.values()
            for m in sig.matchers
            if m.is_pcre
        )
        return {
            "total_rules": len(self.signatures),
            "pcre_rules": pcre_count,
            "aho_corasick": _AHO_AVAILABLE,
        }
