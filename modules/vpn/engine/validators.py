"""
Enterprise bunyanx - VPN Input Validators
=============================================
Defense-in-depth validation for all untrusted VPN inputs before they
reach the WireGuard CLI or are persisted to the database.

Security rationale:
  - WireGuard public keys MUST be exactly 44 Base64 characters (32 bytes
    encoded) ending with '='. Anything else is rejected.
  - Allowed IPs MUST be valid CIDRs. Overly broad ranges are flagged.
  - Endpoints MUST match 'IP:PORT' or '[IPv6]:PORT' format.
  - Ports, MTU and other numeric params are range-checked.
"""

import re
import logging
import ipaddress
from typing import List

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

# WireGuard Curve25519 public key: 32 bytes → 44 Base64 chars (with padding)
_WG_KEY_REGEX = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_WG_KEY_LENGTH = 44

# Endpoint: IPv4:PORT or [IPv6]:PORT
_ENDPOINT_IPV4_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$"
)
_ENDPOINT_IPV6_RE = re.compile(
    r"^\[([0-9a-fA-F:]+)\]:(\d{1,5})$"
)

# Dangerous CIDRs that grant full network access
_DANGEROUS_CIDRS = frozenset(["0.0.0.0/0", "::/0"])

# Peer name: max length and allowed characters
_MAX_PEER_NAME_LENGTH = 128


# ── Public Validators ─────────────────────────────────────────────────────────

class VPNValidationError(ValueError):
    """Raised when a VPN input fails validation."""
    pass


def validate_wireguard_pubkey(key: str) -> str:
    """Validate a WireGuard Curve25519 public key (Base64, 44 chars).

    Args:
        key: The public key string to validate.

    Returns:
        The validated key (stripped).

    Raises:
        VPNValidationError: If the key is invalid.
    """
    if not key or not isinstance(key, str):
        raise VPNValidationError("Public key must be a non-empty string.")

    key = key.strip()

    if len(key) != _WG_KEY_LENGTH:
        raise VPNValidationError(
            f"Public key must be exactly {_WG_KEY_LENGTH} characters, "
            f"got {len(key)}."
        )

    if not _WG_KEY_REGEX.match(key):
        raise VPNValidationError(
            "Public key contains invalid characters. "
            "Expected Base64-encoded Curve25519 key."
        )

    return key


def validate_allowed_ips(cidrs: List[str]) -> List[str]:
    """Validate a list of allowed IP CIDRs for WireGuard peers.

    Args:
        cidrs: List of CIDR strings (e.g., ['10.0.0.0/24', '192.168.1.5/32']).

    Returns:
        List of validated, normalized CIDR strings.

    Raises:
        VPNValidationError: If any CIDR is invalid.
    """
    if not cidrs:
        raise VPNValidationError("allowed_ips must contain at least one CIDR.")

    validated = []
    for cidr in cidrs:
        cidr = cidr.strip()

        # Warn on dangerous full-tunnel CIDRs (allow but log warning)
        if cidr in _DANGEROUS_CIDRS:
            logger.warning(
                "VPN Validator: Dangerous CIDR '%s' in allowed_ips — "
                "grants full network access to peer.", cidr
            )

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            validated.append(str(network))
        except ValueError as exc:
            raise VPNValidationError(
                f"Invalid CIDR '{cidr}': {exc}"
            ) from exc

    return validated


def validate_endpoint(endpoint: str) -> str:
    """Validate a WireGuard peer endpoint (IP:PORT format).

    Args:
        endpoint: Endpoint string, e.g. '203.0.113.1:51820' or '[::1]:51820'.

    Returns:
        The validated endpoint string.

    Raises:
        VPNValidationError: If the format is invalid.
    """
    if not endpoint or not isinstance(endpoint, str):
        raise VPNValidationError("Endpoint must be a non-empty string.")

    endpoint = endpoint.strip()

    # Try IPv4:PORT
    m = _ENDPOINT_IPV4_RE.match(endpoint)
    if m:
        ip_str, port_str = m.group(1), m.group(2)
        try:
            ipaddress.IPv4Address(ip_str)
        except ValueError:
            raise VPNValidationError(f"Invalid IPv4 address in endpoint: '{ip_str}'")
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise VPNValidationError(f"Endpoint port must be 1–65535, got {port}.")
        return endpoint

    # Try [IPv6]:PORT
    m = _ENDPOINT_IPV6_RE.match(endpoint)
    if m:
        ip_str, port_str = m.group(1), m.group(2)
        try:
            ipaddress.IPv6Address(ip_str)
        except ValueError:
            raise VPNValidationError(f"Invalid IPv6 address in endpoint: '{ip_str}'")
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise VPNValidationError(f"Endpoint port must be 1–65535, got {port}.")
        return endpoint

    # Try hostname:PORT (for DNS-resolved endpoints)
    if ":" in endpoint:
        parts = endpoint.rsplit(":", 1)
        if len(parts) == 2:
            host, port_str = parts
            if host and port_str.isdigit():
                port = int(port_str)
                if 1 <= port <= 65535:
                    # Basic hostname validation
                    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', host):
                        return endpoint

    raise VPNValidationError(
        f"Invalid endpoint format: '{endpoint}'. "
        "Expected 'IP:PORT', '[IPv6]:PORT', or 'hostname:PORT'."
    )


def validate_listen_port(port: int) -> int:
    """Validate a WireGuard listen port.

    Args:
        port: UDP port number.

    Returns:
        The validated port.

    Raises:
        VPNValidationError: If the port is out of range.
    """
    if not isinstance(port, int) or port < 1024 or port > 65535:
        raise VPNValidationError(
            f"Listen port must be an integer in range 1024–65535, got {port}."
        )
    return port


def validate_server_ip(cidr: str) -> str:
    """Validate a server IP with prefix length (e.g., '10.10.0.1/24').

    Args:
        cidr: IP address with prefix length.

    Returns:
        The validated CIDR string.

    Raises:
        VPNValidationError: If the format is invalid.
    """
    if not cidr or not isinstance(cidr, str):
        raise VPNValidationError("Server IP must be a non-empty string.")

    cidr = cidr.strip()
    if "/" not in cidr:
        raise VPNValidationError(
            f"Server IP must include prefix length (e.g., '10.10.0.1/24'), "
            f"got '{cidr}'."
        )

    try:
        ipaddress.ip_interface(cidr)
    except ValueError as exc:
        raise VPNValidationError(f"Invalid server IP/CIDR '{cidr}': {exc}") from exc

    return cidr


def validate_mtu(mtu: int) -> int:
    """Validate MTU value for WireGuard tunnel.

    Args:
        mtu: Maximum Transmission Unit.

    Returns:
        The validated MTU.

    Raises:
        VPNValidationError: If the MTU is out of range.
    """
    if not isinstance(mtu, int) or mtu < 1280 or mtu > 1500:
        raise VPNValidationError(
            f"MTU must be in range 1280–1500, got {mtu}."
        )
    return mtu


def sanitize_peer_name(name: str) -> str:
    """Sanitize a peer friendly name — strip HTML, limit length.

    Args:
        name: Raw peer name from user input.

    Returns:
        Sanitized name string.
    """
    if not name:
        return ""

    # Strip HTML tags
    name = re.sub(r"<[^>]+>", "", name)
    # Remove control characters
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    # Trim whitespace and limit length
    name = name.strip()[:_MAX_PEER_NAME_LENGTH]

    return name


def validate_interface_name(interface: str) -> str:
    """Validate interface name format (must be wg followed by digits, e.g., wg0).

    Args:
        interface: The interface name.

    Returns:
        The validated interface name.

    Raises:
        VPNValidationError: If the format is invalid.
    """
    if not interface or not isinstance(interface, str):
        raise VPNValidationError("Interface name must be a non-empty string.")

    if not re.match(r"^wg[0-9]+$", interface):
        raise VPNValidationError(
            f"Interface name must match pattern '^wg[0-9]+$', got '{interface}'."
        )

    return interface
