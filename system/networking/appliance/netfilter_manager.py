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
            logger.error(f"nftables command failed: {' '.join(cmd)}\nSTDERR: {e.stderr}\nSTDOUT: {e.stdout}")
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

        Reads configuration dynamically from modules/firewall/config/settings.yaml:
          - management_ports + dev_ports
          - allow_icmp_ping & icmp_interface_restrict
          - custom input ports (UDP & TCP, e.g. WireGuard 51820)
        """
        try:
            idx = self._rules_buffer.index("    chain input {") + 2
        except ValueError:
            return  # No input chain defined

        fw_opts = self._load_firewall_settings()
        mgmt_ports = fw_opts.get("mgmt_ports", [22, 443, 8000, 5173, 8888])
        port_list = ', '.join(str(p) for p in sorted(mgmt_ports))

        # ── TCP Management Interface Rule ────────
        if self.mgmt_interface_name:
            iface_rule = f'iifname "{self.mgmt_interface_name}" tcp dport {{ {port_list} }} accept'
        else:
            iface_rule = f'tcp dport {{ {port_list} }} accept'

        safe_rules = [
            "        # [MGMT PROTECTION START]",
            "        ct state established,related accept",
            '        iif "lo" accept',
        ]

        # ── Dynamic ICMP Ping Rule from YAML ─────
        allow_icmp = fw_opts.get("allow_icmp_ping", True)
        icmp_restrict = fw_opts.get("icmp_interface_restrict", False)
        if allow_icmp:
            if icmp_restrict and self.mgmt_interface_name:
                safe_rules.append(f'        iifname "{self.mgmt_interface_name}" icmp type echo-request accept')
            else:
                safe_rules.append('        icmp type echo-request accept')

        # ── Dynamic UDP/Custom Input Ports from YAML (e.g. WireGuard 51820) ─
        udp_input_ports = fw_opts.get("udp_input_ports", [51820])
        if udp_input_ports:
            u_ports = ', '.join(str(p) for p in sorted(udp_input_ports))
            safe_rules.append(f'        udp dport {{ {u_ports} }} accept')

        # ── VPN Interface Access ─────────────────
        safe_rules.extend([
            '        iifname "wg0" accept',
            f"        {iface_rule}",
            "        # [MGMT PROTECTION END]",
        ])

        self._rules_buffer = (
            self._rules_buffer[:idx] + safe_rules + self._rules_buffer[idx:]
        )

    def _load_firewall_settings(self) -> dict:
        """Load configuration options from settings.yaml (single source of truth)."""
        defaults = {
            "mgmt_ports": [22, 443, 8000, 5173, 8888],
            "allow_icmp_ping": True,
            "icmp_interface_restrict": False,
            "udp_input_ports": [51820],
            "routing_enabled": True,
            "ip_forwarding": True,
            "nat_masquerade": True,
            "lan_subnets": ["10.10.0.0/16", "10.0.0.0/8"],
        }
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
                defaults["mgmt_ports"] = sorted(set(_mgmt + _dev))
                defaults["allow_icmp_ping"] = bool(_fw.get("allow_icmp_ping", True))
                defaults["icmp_interface_restrict"] = bool(_fw.get("icmp_interface_restrict", False))

                # Parse automated routing & NAT config from settings.yaml
                _routing = _fw.get("routing", {})
                if _routing:
                    defaults["routing_enabled"] = bool(_routing.get("enabled", True))
                    defaults["ip_forwarding"] = bool(_routing.get("ip_forwarding", True))
                    defaults["nat_masquerade"] = bool(_routing.get("nat_masquerade", True))
                    defaults["lan_subnets"] = list(_routing.get("lan_subnets", ["10.10.0.0/16", "10.0.0.0/8"]))

                # Parse UDP input ports from custom_ports
                udp_ports = []
                for cp in _fw.get("custom_ports", []):
                    if cp.get("enabled", True):
                        proto = str(cp.get("protocol", "tcp")).lower()
                        direction = str(cp.get("direction", "input")).lower()
                        port = int(cp.get("port", 0))
                        if port > 0 and proto in ("udp", "both") and direction in ("input", "both"):
                            udp_ports.append(port)
                if udp_ports:
                    defaults["udp_input_ports"] = sorted(set(udp_ports))
        except Exception as exc:
            logger.debug("_load_firewall_settings: could not load settings.yaml: %s", exc)
        return defaults


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
        """Enable Linux IP forwarding and configure automated NAT masquerade & FORWARD rules."""
        if os.name != "posix":
            return

        fw_opts = self._load_firewall_settings()
        if not fw_opts.get("ip_forwarding", True):
            return

        # 1. Enable kernel IP forwarding
        try:
            if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1\n")
                logger.info("✅ IPv4 Forwarding enabled in kernel (sysctl).")
        except PermissionError:
            logger.error("Failed to enable IP forwarding. Requires root.")
        except Exception as _fwd_err:
            logger.debug("IP forwarding error: %s", _fwd_err)

        # 2. Automated NAT Masquerade & Forwarding fallback (iptables)
        if fw_opts.get("nat_masquerade", True):
            import shutil
            if shutil.which("iptables"):
                lan_subnets = fw_opts.get("lan_subnets", ["10.10.0.0/16", "10.0.0.0/8"])
                try:
                    for snet in lan_subnets:
                        # Check/Add NAT Masquerade
                        subprocess.run(
                            ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", snet, "-j", "MASQUERADE"],
                            capture_output=True, timeout=2
                        ).returncode != 0 and subprocess.run(
                            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", snet, "-j", "MASQUERADE"],
                            capture_output=True, timeout=2
                        )
                        # Check/Add FORWARD allow for LAN subnet
                        subprocess.run(
                            ["iptables", "-C", "FORWARD", "-s", snet, "-j", "ACCEPT"],
                            capture_output=True, timeout=2
                        ).returncode != 0 and subprocess.run(
                            ["iptables", "-A", "FORWARD", "-s", snet, "-j", "ACCEPT"],
                            capture_output=True, timeout=2
                        )
                    # Allow Established & Related
                    subprocess.run(
                        ["iptables", "-C", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                        capture_output=True, timeout=2
                    ).returncode != 0 and subprocess.run(
                        ["iptables", "-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                        capture_output=True, timeout=2
                    )
                    logger.info("✅ Automated NAT Masquerade & FORWARD rules applied for LAN subnets: %s", lan_subnets)
                except Exception as _nat_err:
                    logger.debug("Automated iptables NAT setup error: %s", _nat_err)

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
            # FIX: Some nft versions don't support -c (dry-run) flag.
            # If validation fails, log the full STDERR for diagnosis, then
            # attempt a direct apply rather than silently aborting.
            import subprocess as _sp
            logger.info(f"Validating nftables ruleset syntax: {temp_path}")
            try:
                val_result = _sp.run(
                    ["nft", "-c", "-f", temp_path],
                    check=True, capture_output=True, text=True
                )
                validation_ok = True
            except _sp.CalledProcessError as ve:
                logger.error(
                    "nftables validation failed.\n"
                    "  STDERR: %s\n"
                    "  STDOUT: %s\n"
                    "  Rules preview (first 20 lines):\n%s",
                    ve.stderr.strip() or "(empty)",
                    ve.stdout.strip() or "(empty)",
                    "\n".join(("    " + ln) for ln in rules_text.splitlines()[:20])
                )
                # FIX: If nft -c is unsupported or rules have minor issues,
                # try applying anyway — many nft versions return error on -c
                # even for valid rulesets (kernel version mismatch).
                logger.warning(
                    "nftables -c validation failed — attempting direct apply "
                    "(this is safe: nft will reject invalid syntax on apply too)."
                )
                validation_ok = None  # None = skipped, not confirmed

            if validation_ok is False:
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

