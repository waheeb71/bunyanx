#!/usr/bin/env python3
"""
Enterprise bunyanx - Netfilter Abstraction Manager
======================================================
Provides atomic interactions with `nftables`. This layer is designed
to avoid any direct iptables/nft commands in the proxy/routing code.
Instead, it assembles an nftables configuration file, verifies it via
`nft -c -f`, and then atomically loads it via `nft -f`.

Also protects the MGMT interface implicitly from lockout by prepending 
whitelist rules for the MGMT ports.
"""

import os
import subprocess
import logging
from pathlib import Path
from tempfile import NamedTemporaryFile

logger = logging.getLogger(__name__)

class NetfilterManager:
    """Manages system nftables with strict atomic loading and syntax validation."""
    
    def __init__(self, config: dict, mgmt_mac: str = None, mgmt_interface_name: str = None):
        self.config = config
        self.mgmt_mac = mgmt_mac
        # None = no specific interface → MGMT rules apply to all interfaces
        self.mgmt_interface_name = mgmt_interface_name
        self._rules_buffer = []


    def _execute(self, cmd: list) -> bool:
        if os.name != "posix":
            logger.warning(f"Not on POSIX/Linux — ignoring netfilter command: {' '.join(cmd)}")
            return True
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except FileNotFoundError:
            logger.error(f"nftables utility ('{cmd[0]}') is not installed or not in PATH.")
            return False
        except PermissionError:
            logger.error(f"Permission denied while executing: {' '.join(cmd)}. Requires root privileges.")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"nftables command failed: {' '.join(cmd)}\n{e.stderr}")
            return False

    def clear_rules(self):
        """Builds a base empty ruleset that flushes everything safely."""
        self._rules_buffer = [
            "flush ruleset",
            "table inet filter {",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "    }",
            "    chain forward {",
            "        type filter hook forward priority 0; policy drop;",
            "    }",
            "    chain output {",
            "        type filter hook output priority 0; policy accept;",
            "    }",
            "}",
            "table inet nat {",
            "    chain prerouting {",
            "        type nat hook prerouting priority -100; policy accept;",
            "    }",
            "    chain postrouting {",
            "        type nat hook postrouting priority 100; policy accept;",
            "    }",
            "}"
        ]

    def add_mgmt_protection_rules(self):
        """Injects MGMT safe rules into the input chain to prevent lockout.

        Ports are read from modules/firewall/config/settings.yaml
        (management_ports + dev_ports when enabled) so there is a single
        source of truth — never hardcoded here.
        """
        try:
            idx = self._rules_buffer.index("    chain input {") + 2
        except ValueError:
            return  # No input chain defined

        mgmt_ports = self._get_mgmt_ports()
        port_list  = ', '.join(str(p) for p in sorted(mgmt_ports))

        # If mgmt interface is known → restrict to it; otherwise protect all
        if self.mgmt_interface_name:
            iface_rule = f'iifname "{self.mgmt_interface_name}" tcp dport {{ {port_list} }} accept'
            icmp_rule  = f'iifname "{self.mgmt_interface_name}" icmp type echo-request accept'
        else:
            iface_rule = f'tcp dport {{ {port_list} }} accept'
            icmp_rule  = 'icmp type echo-request accept'

        safe_rules = [
            "        # [MGMT PROTECTION START]",
            "        ct state established,related accept",
            '        iif "lo" accept',
            f"        {iface_rule}",
            f"        {icmp_rule}",
            "        # [MGMT PROTECTION END]",
        ]

        self._rules_buffer = (
            self._rules_buffer[:idx] + safe_rules + self._rules_buffer[idx:]
        )

    def _get_mgmt_ports(self) -> list:
        """Load management + dev ports from firewall settings.yaml.
        Falls back to safe defaults if the file cannot be read.
        """
        try:
            import yaml as _yaml
            _root = Path(__file__).resolve().parent.parent.parent.parent
            _settings = _root / 'modules' / 'firewall' / 'config' / 'settings.yaml'
            if _settings.exists():
                with open(_settings, encoding='utf-8') as _f:
                    _raw = _yaml.safe_load(_f) or {}
                _fw = _raw.get('firewall', _raw)
                _mgmt = [int(p) for p in _fw.get('management_ports', [22, 443, 8888])]
                _dev_on = _fw.get('dev_ports_enabled', True)
                _dev = [int(p) for p in _fw.get('dev_ports', [8000, 5173])] if _dev_on else []
                return sorted(set(_mgmt + _dev))
        except Exception as exc:
            logger.debug("_get_mgmt_ports: could not load settings.yaml: %s", exc)
        return [22, 443, 8000, 5173, 8888]  # safe fallback


    def inject_rules(self, chain_name: str, rules_list: list):
        """
        Dynamically injects a list of rules into a specific nftables chain.
        This decouples the NetfilterManager from hardcoded proxy/firewall logic.
        """
        if not rules_list:
            return
            
        try:
            # Find the chain block
            chain_header = f"    chain {chain_name.lower()} {{"
            idx = self._rules_buffer.index(chain_header) + 2
            
            formatted_rules = [f"        {rule}" if not rule.startswith(" ") else rule for rule in rules_list]
            self._rules_buffer = self._rules_buffer[:idx] + formatted_rules + self._rules_buffer[idx:]
            logger.debug(f"Injected {len(rules_list)} rules into chain '{chain_name}'")
        except ValueError:
            logger.warning(f"Could not find chain '{chain_name}' to inject rules.")

    def enable_ip_forwarding(self):
        """Enable Linux IP forwarding globally."""
        if os.name != "posix" or not os.path.exists("/proc/sys/net/ipv4/ip_forward"):
            return
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            logger.info("IPv4 Forwarding enabled natively.")
        except PermissionError:
            logger.error("Failed to enable IP forwarding. Requires root.")

    def apply_atomic(self) -> bool:
        """
        Validates syntax and applies atomically.
        FIX P6: Write temp ruleset to /run/bunyanx/ (root-owned tmpfs) instead
        of the world-writable /tmp to prevent symlink injection attacks.
        """
        rules_text = "\n".join(self._rules_buffer)

        # Create a secure temp directory owned by root (tmpfs, non-world-writable)
        secure_tmp = Path("/run/bunyanx")
        try:
            secure_tmp.mkdir(parents=True, exist_ok=True)
            secure_tmp.chmod(0o700)
        except Exception:
            secure_tmp = Path("/tmp")   # fallback to /tmp if /run unavailable

        with NamedTemporaryFile(
            mode='w', suffix='.nft', delete=False,
            dir=str(secure_tmp)
        ) as temp_nft:
            temp_nft.write(rules_text)
            temp_path = temp_nft.name

        try:
            # 1. Validation (Dry run syntax check)
            logger.info(f"Validating nftables ruleset syntax: {temp_path}")
            if not self._execute(["nft", "-c", "-f", temp_path]):
                logger.error("nftables validation failed. Aborting atomic apply.")
                return False

            # 2. Atomic Apply
            logger.info("Applying nftables atomically...")
            if self._execute(["nft", "-f", temp_path]):
                logger.info("✅ nftables active.")
                return True
            return False

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

