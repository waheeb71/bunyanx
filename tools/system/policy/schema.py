"""
Enterprise bunyanx Policy Schema
Data models for policy rules and definitions.
"""

from typing import List, Optional, Dict, Union, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import uuid

class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REJECT = "reject"  # Send RST/ICMP unreachable
    MONITOR = "monitor"  # Log but allow
    CHALLENGE = "challenge"  # CAPTCHA/Auth
    RATE_LIMIT = "rate_limit"  # ✨ NEW: Apply rate limiting
    QUARANTINE = "quarantine"  # ✨ NEW: Isolate suspicious traffic
    LOG_ONLY = "log_only"  # ✨ NEW: Only log, no action
    DECEIVE = "deceive"  # ✨ NEW: Send deceptive payloads/tarpits to prove intent

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

@dataclass
class TimeSchedule:
    """Time-based restriction"""
    name: str
    days: List[str] # ["Mon", "Tue"...]
    start_time: str # "09:00"
    end_time: str   # "17:00"
    timezone: str = "UTC"

@dataclass
class BaseRule:
    """Base class for all policy rules"""
    name: str
    action: Action
    enabled: bool = True
    priority: int = 100
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    schedule: Optional[TimeSchedule] = None
    log: bool = True
    tags: List[str] = field(default_factory=list)

@dataclass
class FirewallRule(BaseRule):
    """Layer 3/4 Access Control Rule"""
    src_zone: str = "any" # LAN, WAN, DMZ
    dst_zone: str = "any"
    src_ip: Optional[Union[str, List[str]]] = None # CIDR or IP
    dst_ip: Optional[Union[str, List[str]]] = None
    src_port: Optional[Union[int, str]] = None # "80", "1024-65535"
    dst_port: Optional[Union[int, str]] = None
    protocol: Protocol = Protocol.ANY

@dataclass
class AppRule(BaseRule):
    """Layer 7 Application Control Rule"""
    application: str = "any" # "facebook", "bittorrent"
    category: Optional[str] = None # "social-media", "p2p"
    users: List[str] = field(default_factory=list) # User/Group names
    bandwidth_limit: Optional[int] = None # kbps

@dataclass
class WebFilterRule(BaseRule):
    """Web/URL Filtering Rule"""
    categories: List[str] = field(default_factory=list) # "gambling", "adult"
    exact_urls: List[str] = field(default_factory=list)
    block_file_types: List[str] = field(default_factory=list) # "exe", "zip"
    safe_search: bool = False

@dataclass
class IPSRule(BaseRule):
    """Intrusion Prevention Rule"""
    signature_id: Optional[str] = None
    severity_threshold: Optional[str] = None # "high", "critical"

@dataclass
class VPNRule(BaseRule):
    """
    VPN Access Control Rule.

    Controls which users/groups/IPs are permitted to establish
    WireGuard VPN connections, and what they can access through the tunnel.
    """
    # Who this rule applies to
    allowed_users: List[str] = field(default_factory=list)    # usernames or "*"
    allowed_groups: List[str] = field(default_factory=list)   # roles / LDAP groups

    # Source IP restrictions (peer's real IP before tunneling)
    src_ip_whitelist: List[str] = field(default_factory=list) # CIDRs; empty = any

    # Tunnel scope (split tunneling)
    allowed_networks: List[str] = field(default_factory=list) # CIDRs routed over VPN
    excluded_networks: List[str] = field(default_factory=list)# CIDRs bypassed

    # Authentication requirements
    require_mfa: bool = False
    session_timeout_minutes: int = 480  # 8 hours default

    # WireGuard interface this rule applies to ("wg0" or "*")
    interface: str = "*"

    def allows_user(self, username: str, role: str) -> bool:
        """Check if a user is permitted by this rule."""
        if not self.enabled:
            return False
        if "*" in self.allowed_users or username in self.allowed_users:
            return True
        if "*" in self.allowed_groups or role in self.allowed_groups:
            return True
        return False


@dataclass
class PolicyContext:
    """Context for policy evaluation"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    interface: str = "unknown"
    app_id: Optional[str] = None
    user_id: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class VPNPolicyContext:
    """Context for VPN-specific policy evaluation."""
    username: str
    role: str
    peer_public_key: str
    peer_real_ip: str          # IP before tunneling
    requested_allowed_ips: List[str]
    interface: str = "wg0"
    timestamp: datetime = field(default_factory=datetime.now)

