"""
Firewall Config Validator (M9)
================================
Validates the firewall config dict at startup using Python dataclasses.
Raises ValueError on the first detected misconfiguration to fail fast.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

VALID_MODES = {"enforce", "monitor"}
VALID_POLICIES = {"DROP", "ALLOW"}


@dataclass
class GeoIPConfig:
    db_path: str = "system/data/GeoIP2-City.mmdb"
    asn_db_path: str = "system/data/GeoLite2-ASN.mmdb"
    blocked_countries: List[str] = field(default_factory=list)
    whitelisted_countries: List[str] = field(default_factory=list)


@dataclass
class CustomPort:
    name: str
    port: int
    protocol: str = "tcp"
    direction: str = "input"
    enabled: bool = True



@dataclass
class FirewallConfig:
    enabled: bool = True
    mode: str = "enforce"
    default_policy: str = "DROP"
    state_timeout_seconds: int = 300
    max_active_connections: int = 100000
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)
    zones: dict = field(default_factory=dict)
    # Management ports — always allowed from settings.yaml
    management_ports: List[int] = field(default_factory=list)
    # Dev/proxy bypass ports — configurable from settings.yaml
    dev_ports_enabled: bool = False
    dev_ports: List[int] = field(default_factory=list)
    # Unlimited dynamic custom ports
    custom_ports: List[CustomPort] = field(default_factory=list)


    def validate(self):
        """Raise ValueError if any config value is invalid."""
        if self.mode not in VALID_MODES:
            raise ValueError(
                f"[FirewallConfig] Invalid mode '{self.mode}'. Valid: {VALID_MODES}"
            )

        if self.default_policy.upper() not in VALID_POLICIES:
            raise ValueError(
                f"[FirewallConfig] Invalid default_policy '{self.default_policy}'. Valid: {VALID_POLICIES}"
            )

        if self.state_timeout_seconds <= 0:
            raise ValueError(
                f"[FirewallConfig] state_timeout_seconds must be > 0, got {self.state_timeout_seconds}"
            )

        if self.max_active_connections <= 0:
            raise ValueError(
                f"[FirewallConfig] max_active_connections must be > 0, got {self.max_active_connections}"
            )

        for code in self.geoip.blocked_countries:
            if len(code) != 2 or not code.isalpha():
                raise ValueError(
                    f"[FirewallConfig] Invalid blocked_country code '{code}'. Must be 2-letter ISO code."
                )

        for code in self.geoip.whitelisted_countries:
            if len(code) != 2 or not code.isalpha():
                raise ValueError(
                    f"[FirewallConfig] Invalid whitelisted_country code '{code}'. Must be 2-letter ISO code."
                )

        # Cross-validation: warn if a country is in both whitelist and blacklist
        overlap = set(self.geoip.blocked_countries) & set(self.geoip.whitelisted_countries)
        if overlap:
            logger.warning(
                "[FirewallConfig] Country codes %s appear in BOTH blocked and whitelisted lists. "
                "Whitelist takes priority — these countries will NOT be blocked.",
                sorted(overlap),
            )

        # Validate Custom Ports
        for cp in self.custom_ports:
            if not (1 <= cp.port <= 65535):
                raise ValueError(f"[FirewallConfig] Invalid custom port number {cp.port} for '{cp.name}'")
            if cp.protocol.lower() not in {"tcp", "udp", "both"}:
                raise ValueError(f"[FirewallConfig] Invalid protocol '{cp.protocol}' for custom port '{cp.name}'. Must be tcp, udp, or both.")
            if cp.direction.lower() not in {"input", "forward", "both"}:
                raise ValueError(f"[FirewallConfig] Invalid direction '{cp.direction}' for custom port '{cp.name}'. Must be input, forward, or both.")

        logger.info(
            "[FirewallConfig] Validation passed — mode=%s | default=%s | max_conn=%d",
            self.mode, self.default_policy, self.max_active_connections
        )


def validate_firewall_config(raw_config: dict) -> FirewallConfig:
    """
    Parse and validate a raw config dict from settings.yaml.
    Returns a validated FirewallConfig dataclass.
    Raises ValueError on any misconfiguration — call this at startup.
    """
    fw_conf = raw_config.get("firewall", raw_config)

    geoip_raw = fw_conf.get("geoip", {})
    geoip = GeoIPConfig(
        db_path=geoip_raw.get("db_path", "system/data/GeoIP2-City.mmdb"),
        asn_db_path=geoip_raw.get("asn_db_path", "system/data/GeoLite2-ASN.mmdb"),
        blocked_countries=geoip_raw.get("blocked_countries", []),
        whitelisted_countries=geoip_raw.get("whitelisted_countries", []),
    )

    # Parse custom_ports
    custom_ports_raw = fw_conf.get("custom_ports", [])
    parsed_custom_ports = []
    for cp in custom_ports_raw:
        parsed_custom_ports.append(CustomPort(
            name=cp.get("name", "Unknown"),
            port=int(cp.get("port", 0)),
            protocol=str(cp.get("protocol", "tcp")).lower(),
            direction=str(cp.get("direction", "input")).lower(),
            enabled=bool(cp.get("enabled", True))
        ))

    config = FirewallConfig(
        enabled=fw_conf.get("enabled", True),
        mode=str(fw_conf.get("mode", "enforce")),
        default_policy=str(fw_conf.get("default_policy", "DROP")).upper(),
        state_timeout_seconds=int(fw_conf.get("state_timeout_seconds", 300)),
        max_active_connections=int(fw_conf.get("max_active_connections", 100000)),
        geoip=geoip,
        zones=fw_conf.get("zones", {}),
        management_ports=[int(p) for p in fw_conf.get("management_ports", [])],
        dev_ports_enabled=bool(fw_conf.get("dev_ports_enabled", False)),
        dev_ports=[int(p) for p in fw_conf.get("dev_ports", [])],
        custom_ports=parsed_custom_ports,
    )

    config.validate()
    return config
