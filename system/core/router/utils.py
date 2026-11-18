"""
Router Utilities
Helper functions for traffic analysis and extraction.
"""

import logging
import re
from typing import Tuple, Optional, Any
from .types import ProxyMode

logger = logging.getLogger(__name__)

# Basic validation for domains and IPs to prevent policy engine injection
VALID_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")

async def extract_target(data: bytes, mode: ProxyMode) -> Tuple[Optional[str], Optional[int]]:
    """
    Extract target host/port from initial connection data
    
    Handles:
    - HTTP CONNECT requests
    - TLS SNI
    """
    # Check for HTTP CONNECT
    if data.startswith(b'CONNECT'):
        try:
            line = data.split(b'\r\n')[0].decode('latin-1')
            parts = line.split()
            if len(parts) >= 2:
                target = parts[1].split(':')
                host = target[0]
                port = int(target[1]) if len(target) > 1 else 443
                return host, port
        except Exception as e:
            logger.debug(f"Error parsing CONNECT: {e}")
    
    # Check for TLS ClientHello (SNI)
    if len(data) > 5 and data[0] == 0x16:
        # Use the dedicated SNI utility in system/networking — no module dependency.
        try:
            from system.networking.sni_utils import extract_sni
            sni = extract_sni(data)
            if sni:
                return sni, 443
        except Exception:
            logger.warning("SNI parse failed")
            
    # Check for raw HTTP (GET, POST, PUT, DELETE, etc.)
    if data.startswith((b'GET ', b'POST ', b'PUT ', b'HEAD ', b'OPTIONS ', b'DELETE ', b'PATCH ')):
        try:
            # Fast raw bytes parsing to avoid full payload decoding overhead
            headers_end = data.find(b'\r\n\r\n')
            headers_data = data[:headers_end] if headers_end != -1 else data
            
            for line in headers_data.split(b'\r\n'):
                if line.lower().startswith(b'host:'):
                    host_part = line[5:].strip().decode('latin-1')
                    host = host_part
                    port = 80
                    if ':' in host_part:
                        parts = host_part.split(':', 1)
                        host = parts[0]
                        try:
                            port = int(parts[1])
                        except ValueError:
                            pass
                    
                    # Sanitize to prevent injection
                    if VALID_DOMAIN_RE.match(host):
                        return host, port
                    else:
                        logger.warning(f"Invalid characters in HTTP Host header: {host}")
                        return None, None
        except Exception as e:
            logger.debug(f"Error parsing HTTP Host: {e}")
            
    return None, None

def match_domain(domain: str, pattern: str) -> bool:
    """Match domain against pattern (supports wildcards)"""
    import re
    regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
    return bool(re.match(f'^{regex_pattern}$', domain, re.IGNORECASE))
