#!/usr/bin/env python3
"""
Enterprise bunyanx - Intelligent Network Auto-Configurator
================================================================
Automatically configures all network interfaces on first boot
by reading base.yaml and applying addresses using the `ip` command.

Features:
  1. Auto-discovery of all physical NICs via /sys/class/net
  2. Intelligent role assignment (WAN vs LAN) based on:
     - MAC address matching (if configured in base.yaml)
     - Auto-detection: USB adapter → WAN, built-in → LAN
  3. Applies static IPs for LAN/Management, DHCP for WAN
  4. Enables IP forwarding (sysctl)
  5. Sets up NAT masquerading via nftables
  6. Configures default routes
  7. Idempotent: safe to run multiple times
  8. State tracking: saves applied state to avoid re-applying

Run order: This runs BEFORE the firewall engine starts.
"""

import os
import sys
import re
import json
import time
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger("bunyanx.network.auto_config")

# ─── Constants ────────────────────────────────────────────────────────────────
STATE_FILE = Path("/etc/bunyanx/network_applied_state.json")
SYSCTL_FORWARDING = "/proc/sys/net/ipv4/ip_forward"
SYS_NET = Path("/sys/class/net")

# Prefixes that indicate a USB network adapter on Linux
USB_PREFIXES = ("enx", "usb", "wlx")
# Prefixes for built-in NICs
BUILTIN_PREFIXES = ("ens", "enp", "eth", "eno")
# Skip these interfaces
SKIP_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "wg", "tun", "tap")


@dataclass
class NICDevice:
    """Represents a discovered physical network interface."""
    name: str
    mac: str
    is_up: bool
    speed_mbps: int = 0
    is_usb: bool = False
    driver: str = ""
    pci_slot: str = ""


@dataclass
class AppliedState:
    """Tracks what was last applied to avoid redundant reconfigurations."""
    timestamp: str = ""
    wan_device: str = ""
    wan_mac: str = ""
    wan_mode: str = ""
    lan_device: str = ""
    lan_mac: str = ""
    lan_address: str = ""
    mgmt_device: str = ""
    mgmt_mac: str = ""
    mgmt_address: str = ""
    ip_forwarding: bool = False
    nat_configured: bool = False
    config_hash: str = ""


class NetworkAutoConfigurator:
    """
    Intelligent Network Auto-Configurator for bunyanx.
    
    Reads interface configuration from base.yaml and automatically:
    - Discovers all physical NICs
    - Maps roles (WAN, LAN, Management) to NICs
    - Applies IP addresses
    - Enables IP forwarding
    - Configures NAT/masquerading
    """

    def __init__(self, config: dict):
        self.config = config
        self._interfaces_conf = config.get("interfaces", {})
        self._applied_state = AppliedState()
        self._discovered_nics: List[NICDevice] = []
        self._role_map: Dict[str, NICDevice] = {}  # role -> NICDevice

    # ═══════════════════════════════════════════════════════════════
    #  Phase 0: Pre-flight Checks
    # ═══════════════════════════════════════════════════════════════

    def preflight_check(self) -> bool:
        """Verify we're on Linux with root privileges."""
        if os.name != "posix":
            logger.warning("⚠️  Network auto-config requires Linux. Skipping on %s.", os.name)
            return False
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            logger.warning("⚠️  Network auto-config requires root privileges. Skipping.")
            return False
        if not SYS_NET.exists():
            logger.warning("⚠️  /sys/class/net not found. Skipping.")
            return False
        return True

    # ═══════════════════════════════════════════════════════════════
    #  Phase 1: Discovery — Scan All Physical NICs
    # ═══════════════════════════════════════════════════════════════

    def discover_nics(self) -> List[NICDevice]:
        """Scan /sys/class/net and return all physical NICs."""
        nics = []

        for nic_path in sorted(SYS_NET.iterdir()):
            name = nic_path.name

            # Skip virtual/container interfaces
            if any(name.startswith(p) for p in SKIP_PREFIXES):
                continue

            # Skip non-physical (check for device/driver symlink)
            device_path = nic_path / "device"
            if not device_path.exists():
                continue  # No PCI/USB device backing → virtual

            try:
                # Read MAC
                mac_file = nic_path / "address"
                mac = mac_file.read_text().strip().upper() if mac_file.exists() else ""
                if not mac or mac == "00:00:00:00:00:00":
                    continue

                # Normalize MAC to use dashes (for config matching)
                mac_normalized = mac.replace(":", "-")

                # Read state
                operstate = nic_path / "operstate"
                is_up = operstate.read_text().strip() in ("up", "unknown") if operstate.exists() else False

                # Read speed
                speed = 0
                speed_file = nic_path / "speed"
                if speed_file.exists():
                    try:
                        speed = int(speed_file.read_text().strip())
                    except (ValueError, OSError):
                        pass

                # Detect USB vs built-in
                is_usb = any(name.startswith(p) for p in USB_PREFIXES)
                if not is_usb:
                    # Check driver path for USB
                    try:
                        driver_link = (nic_path / "device" / "driver").resolve()
                        driver_name = driver_link.name if driver_link.exists() else ""
                        if "usb" in str(driver_link).lower():
                            is_usb = True
                    except (OSError, RuntimeError):
                        driver_name = ""
                else:
                    driver_name = ""

                nic = NICDevice(
                    name=name,
                    mac=mac_normalized,
                    is_up=is_up,
                    speed_mbps=speed,
                    is_usb=is_usb,
                    driver=driver_name,
                )
                nics.append(nic)
                logger.info(
                    "  🔍 Found NIC: %-16s MAC=%-18s Up=%-5s Speed=%-6s USB=%s",
                    name, mac_normalized, is_up, f"{speed}M" if speed > 0 else "N/A", is_usb
                )

            except Exception as e:
                logger.debug("Could not read NIC %s: %s", name, e)

        self._discovered_nics = nics
        logger.info("📡 Discovery complete: %d physical NIC(s) found.", len(nics))
        return nics
    

    # ═══════════════════════════════════════════════════════════════
    #  Phase 2: Role Mapping — Assign WAN/LAN/MGMT to NICs
    # ═══════════════════════════════════════════════════════════════

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC to XX-XX-XX-XX-XX-XX format."""
        return mac.upper().replace(":", "-")

    def _find_nic_by_mac(self, mac: str) -> Optional[NICDevice]:
        """Find a NIC by MAC address."""
        target = self._normalize_mac(mac)
        for nic in self._discovered_nics:
            if self._normalize_mac(nic.mac) == target:
                return nic
        return None

    def assign_roles(self) -> Dict[str, NICDevice]:
        """
        Assign roles to discovered NICs using a priority system:
        
        1. If base.yaml has MAC addresses → use exact match
        2. If no MACs → auto-detect:
           - USB adapter → WAN (connects to router)
           - Built-in NIC → LAN/MGMT (internal network)
        """
        role_map: Dict[str, NICDevice] = {}
        used_nics = set()

        # ── Step 1: Try MAC-based matching from config ──
        for role in ("management", "wan", "lan"):
            role_conf = self._interfaces_conf.get(role, {})
            mac = role_conf.get("mac", "")
            if mac:
                nic = self._find_nic_by_mac(mac)
                if nic:
                    role_map[role] = nic
                    used_nics.add(nic.name)
                    logger.info("  ✅ %s → %s (MAC match: %s)", role.upper(), nic.name, mac)
                else:
                    logger.warning("  ⚠️  %s MAC %s not found among discovered NICs!", role.upper(), mac)

        # ── Step 2: Auto-assign remaining roles ──
        available = [n for n in self._discovered_nics if n.name not in used_nics]

        # WAN: prefer USB adapters (they typically connect to the router)
        if "wan" not in role_map:
            usb_nics = [n for n in available if n.is_usb]
            if usb_nics:
                # Prefer the one that's UP
                wan_nic = next((n for n in usb_nics if n.is_up), usb_nics[0])
                role_map["wan"] = wan_nic
                used_nics.add(wan_nic.name)
                available = [n for n in available if n.name not in used_nics]
                logger.info("  🔄 WAN → %s (auto-detected USB adapter)", wan_nic.name)

        # LAN/Management: prefer built-in NICs
        if "lan" not in role_map or "management" not in role_map:
            builtin_nics = [n for n in available if not n.is_usb]
            if not builtin_nics:
                builtin_nics = available  # Fallback to any remaining

            if builtin_nics:
                lan_nic = next((n for n in builtin_nics if n.is_up), builtin_nics[0])

                if "lan" not in role_map:
                    role_map["lan"] = lan_nic
                    logger.info("  🔄 LAN → %s (auto-detected built-in)", lan_nic.name)
                if "management" not in role_map:
                    role_map["management"] = lan_nic
                    logger.info("  🔄 MGMT → %s (shares LAN interface)", lan_nic.name)
                used_nics.add(lan_nic.name)

        # ── Step 3: Update base.yaml MAC addresses if they were empty ──
        self._update_config_macs(role_map)

        self._role_map = role_map
        return role_map

    def _update_config_macs(self, role_map: Dict[str, NICDevice]):
        """Update in-memory config with discovered MACs for roles that had empty MACs."""
        for role, nic in role_map.items():
            role_conf = self._interfaces_conf.get(role, {})
            if not role_conf.get("mac"):
                role_conf["mac"] = nic.mac
                self._interfaces_conf[role] = role_conf
                logger.info("  📝 Updated config: %s.mac = %s", role, nic.mac)

    # ═══════════════════════════════════════════════════════════════
    #  Phase 3: Apply — Configure IP Addresses
    # ═══════════════════════════════════════════════════════════════

    def _run_cmd(self, cmd: list, desc: str = "", check: bool = True) -> bool:
        """Execute a system command safely."""
        cmd_str = " ".join(cmd)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0 and check:
                logger.warning("  ⚠️  [%s] Command failed: %s → %s", desc, cmd_str, result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            logger.error("  ❌ [%s] Command not found: %s", desc, cmd[0])
            return False
        except subprocess.TimeoutExpired:
            logger.error("  ❌ [%s] Command timed out: %s", desc, cmd_str)
            return False
        except Exception as e:
            logger.error("  ❌ [%s] Unexpected error: %s", desc, e)
            return False

    def _flush_addresses(self, device: str):
        """Remove all existing IP addresses from a device."""
        self._run_cmd(["ip", "addr", "flush", "dev", device], f"flush {device}", check=False)

    def _set_link_up(self, device: str):
        """Bring a network interface up."""
        self._run_cmd(["ip", "link", "set", device, "up"], f"link up {device}")

    def _add_address(self, device: str, address: str) -> bool:
        """Add an IP address to a device (idempotent)."""
        # Check if already assigned
        try:
            result = subprocess.run(
                ["ip", "addr", "show", "dev", device],
                capture_output=True, text=True, timeout=10
            )
            # Extract the IP without prefix for comparison
            addr_base = address.split("/")[0]
            if addr_base in result.stdout:
                logger.info("  ℹ️  Address %s already assigned to %s", address, device)
                return True
        except Exception:
            pass

        return self._run_cmd(["ip", "addr", "add", address, "dev", device], f"add {address} to {device}")

    def _request_dhcp(self, device: str) -> bool:
        """Request an IP via DHCP for WAN interface."""
        # Try dhclient first, then dhcpcd
        for dhcp_client in ("dhclient", "dhcpcd"):
            try:
                result = subprocess.run(
                    ["which", dhcp_client],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    # Release any existing lease
                    self._run_cmd([dhcp_client, "-r", device], f"DHCP release {device}", check=False)
                    time.sleep(1)
                    # Request new lease (with timeout)
                    if dhcp_client == "dhclient":
                        success = self._run_cmd(
                            [dhcp_client, "-v", "-1", device],
                            f"DHCP request {device}"
                        )
                    else:
                        success = self._run_cmd(
                            [dhcp_client, "-1", device],
                            f"DHCP request {device}"
                        )
                    if success:
                        logger.info("  ✅ DHCP lease obtained on %s via %s", device, dhcp_client)
                        return True
            except Exception:
                continue

        logger.warning("  ⚠️  No DHCP client found (dhclient/dhcpcd). WAN may need manual DHCP.")
        return False

    def apply_addresses(self) -> bool:
        """Apply IP addresses to all mapped interfaces."""
        if not self._role_map:
            logger.error("❌ No role mapping available. Run assign_roles() first.")
            return False

        success = True

        # ── Management Interface ──
        if "management" in self._role_map:
            nic = self._role_map["management"]
            mgmt_conf = self._interfaces_conf.get("management", {})
            address = mgmt_conf.get("address", "10.10.0.1/24")

            logger.info("🔧 Configuring MANAGEMENT: %s → %s", nic.name, address)
            self._set_link_up(nic.name)
            if not self._add_address(nic.name, address):
                # Flush and retry (address conflict)
                self._flush_addresses(nic.name)
                if not self._add_address(nic.name, address):
                    logger.error("  ❌ Failed to assign MGMT address %s to %s", address, nic.name)
                    success = False

            self._applied_state.mgmt_device = nic.name
            self._applied_state.mgmt_mac = nic.mac
            self._applied_state.mgmt_address = address

        # ── LAN Interface (may share with MGMT) ──
        if "lan" in self._role_map:
            nic = self._role_map["lan"]
            lan_conf = self._interfaces_conf.get("lan", {})
            address = lan_conf.get("address", "10.10.0.1/24")

            # If LAN shares the same device as MGMT, skip address assignment
            # (it's already configured)
            mgmt_nic = self._role_map.get("management")
            if mgmt_nic and mgmt_nic.name == nic.name:
                logger.info("🔧 LAN shares MANAGEMENT interface (%s). Address already applied.", nic.name)
            else:
                logger.info("🔧 Configuring LAN: %s → %s", nic.name, address)
                self._set_link_up(nic.name)
                if not self._add_address(nic.name, address):
                    self._flush_addresses(nic.name)
                    if not self._add_address(nic.name, address):
                        logger.error("  ❌ Failed to assign LAN address %s to %s", address, nic.name)
                        success = False

            self._applied_state.lan_device = nic.name
            self._applied_state.lan_mac = nic.mac
            self._applied_state.lan_address = address

        # ── WAN Interface ──
        if "wan" in self._role_map:
            nic = self._role_map["wan"]
            wan_conf = self._interfaces_conf.get("wan", {})
            mode = wan_conf.get("mode", "dhcp")

            logger.info("🔧 Configuring WAN: %s (mode: %s)", nic.name, mode)
            self._set_link_up(nic.name)

            if mode == "dhcp":
                self._request_dhcp(nic.name)
            else:
                address = wan_conf.get("address", "")
                if address:
                    if not self._add_address(nic.name, address):
                        self._flush_addresses(nic.name)
                        self._add_address(nic.name, address)
                    gateway = wan_conf.get("gateway")
                    if gateway:
                        self._run_cmd(
                            ["ip", "route", "add", "default", "via", gateway, "dev", nic.name],
                            "default route", check=False
                        )

            self._applied_state.wan_device = nic.name
            self._applied_state.wan_mac = nic.mac
            self._applied_state.wan_mode = mode

        return success

    # ═══════════════════════════════════════════════════════════════
    #  Phase 4: Enable IP Forwarding & NAT
    # ═══════════════════════════════════════════════════════════════

    def enable_ip_forwarding(self) -> bool:
        """Enable kernel IP forwarding for packet routing."""
        try:
            # Enable immediately
            Path(SYSCTL_FORWARDING).write_text("1")
            logger.info("✅ IP forwarding enabled (sysctl)")

            # Make persistent via sysctl.conf
            sysctl_conf = Path("/etc/sysctl.d/99-bunyanx-forwarding.conf")
            sysctl_conf.parent.mkdir(parents=True, exist_ok=True)
            sysctl_conf.write_text(
                "# bunyanx: Enable IP forwarding for firewall routing\n"
                "net.ipv4.ip_forward = 1\n"
                "net.ipv6.conf.all.forwarding = 1\n"
            )
            logger.info("✅ IP forwarding persisted to %s", sysctl_conf)
            self._applied_state.ip_forwarding = True
            return True

        except PermissionError:
            logger.error("❌ Cannot enable IP forwarding — permission denied")
            return False
        except Exception as e:
            logger.error("❌ Failed to enable IP forwarding: %s", e)
            return False

    def configure_nat(self) -> bool:
        """Set up NAT masquerading so LAN clients can reach the internet via WAN."""
        wan_nic = self._role_map.get("wan")
        if not wan_nic:
            logger.warning("⚠️  No WAN interface mapped. Skipping NAT configuration.")
            return False

        lan_conf = self._interfaces_conf.get("lan", {})
        lan_address = lan_conf.get("address", "10.10.0.1/24")
        # Extract subnet from address (e.g., 10.10.0.1/24 → 10.10.0.0/24)
        try:
            parts = lan_address.split("/")
            ip_parts = parts[0].split(".")
            ip_parts[-1] = "0"
            lan_subnet = ".".join(ip_parts) + "/" + parts[1]
        except (IndexError, ValueError):
            lan_subnet = "10.10.0.0/24"

        # Build nftables NAT rules
        nat_rules = f"""#!/usr/sbin/nft -f
# bunyanx Auto-NAT: LAN → WAN masquerade
# Generated by NetworkAutoConfigurator at {datetime.now().isoformat()}

table ip bunyanx_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        # Masquerade all traffic from LAN subnet going out via WAN
        ip saddr {lan_subnet} oifname "{wan_nic.name}" masquerade
    }}
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
    }}
}}
"""
        # Write and apply atomically
        nat_file = Path("/tmp/bunyanx_nat.nft")
        try:
            nat_file.write_text(nat_rules)
            result = subprocess.run(
                ["nft", "-f", str(nat_file)],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                logger.error("❌ Failed to apply NAT rules: %s", result.stderr.strip())
                return False

            logger.info("✅ NAT masquerading configured: %s → %s (%s)", lan_subnet, wan_nic.name, "masquerade")
            self._applied_state.nat_configured = True

            # Save rules persistently
            persistent_nat = Path("/etc/bunyanx/nat_rules.nft")
            persistent_nat.parent.mkdir(parents=True, exist_ok=True)
            persistent_nat.write_text(nat_rules)

            return True

        except FileNotFoundError:
            logger.error("❌ nft command not found. Install nftables: sudo apt install nftables")
            return False
        except Exception as e:
            logger.error("❌ NAT configuration failed: %s", e)
            return False
        finally:
            nat_file.unlink(missing_ok=True)

    # ═══════════════════════════════════════════════════════════════
    #  Phase 5: Host Firewall Exceptions (Management Ports)
    # ═══════════════════════════════════════════════════════════════

    def open_management_ports(self) -> bool:
        """
        [EMERGENCY USE ONLY]

        Opens management ports directly on the host OS firewall using nft/iptables/ufw.

        This method is NO LONGER called from auto_configure().
        FirewallPlugin (modules/firewall/engine/firewall_plugin.py) is the
        single authority for all nftables INPUT/FORWARD rules, reading directly
        from modules/firewall/config/settings.yaml.

        This method exists only as a fallback for manual emergency access
        recovery (e.g. locked out of management UI) and may be called directly
        from a CLI tool or recovery script if needed.

        Ports are read from modules/firewall/config/settings.yaml (single source).
        """
        import shutil
        ports_to_open = self._get_required_ports()
        logger.info("Opening ports on host firewall: %s", ports_to_open)

        if os.name != "posix":
            logger.info("Non-POSIX system — skipping firewall port rules.")
            return True

        try:
            # ── Detect active firewall tool ──────────────────────────────────

            has_nft     = shutil.which("nft")      is not None
            has_ipt     = shutil.which("iptables") is not None

            # UFW: only treat as active if `ufw status` says "Status: active"
            ufw_active = False
            if shutil.which("ufw"):
                r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
                ufw_active = "Status: active" in r.stdout

            opened = []
            tcp_ports, udp_ports = self._get_required_ports()

            # ── 1. nftables path ─────────────────────────────────────────────
            if has_nft:
                # Check if the inet filter input chain exists
                check = subprocess.run(
                    ["nft", "list", "chain", "inet", "filter", "input"],
                    capture_output=True, text=True
                )
                if check.returncode == 0:
                    # Insert ESTABLISHED/RELATED rule (idempotent guard)
                    est_rule = "ct state established,related accept"
                    if est_rule not in check.stdout:
                        subprocess.run(
                            ["nft", "insert", "rule", "inet", "filter", "input",
                             "ct", "state", "established,related", "accept"],
                            capture_output=True
                        )

                    # Insert loopback accept
                    if 'iif "lo" accept' not in check.stdout:
                        subprocess.run(
                            ["nft", "insert", "rule", "inet", "filter", "input",
                             "iif", "lo", "accept"],
                            capture_output=True
                        )

                    # Insert TCP port rules
                    if tcp_ports:
                        tcp_expr = "{ " + ", ".join(str(p) for p in sorted(tcp_ports)) + " }"
                        subprocess.run(
                            ["nft", "add", "rule", "inet", "filter", "input",
                             "tcp", "dport", tcp_expr, "accept"],
                            capture_output=True
                        )

                    # Insert UDP port rules (e.g. WireGuard 51820 & DNS 53)
                    if udp_ports:
                        udp_expr = "{ " + ", ".join(str(p) for p in sorted(udp_ports)) + " }"
                        subprocess.run(
                            ["nft", "add", "rule", "inet", "filter", "input",
                             "udp", "dport", udp_expr, "accept"],
                            capture_output=True
                        )

                    opened = sorted(set(tcp_ports + udp_ports))
                    logger.info("✅ Ports opened via nftables (TCP: %s, UDP: %s)", tcp_ports, udp_ports)
                    return True
                else:
                    logger.debug("nftables inet filter input chain not found — falling through to iptables.")

            # ── 2. iptables path ─────────────────────────────────────────────
            if has_ipt and not ufw_active:
                # Ensure ESTABLISHED/RELATED rule exists at top of INPUT
                est_check = subprocess.run(
                    ["iptables", "-C", "INPUT", "-m", "conntrack",
                     "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                    capture_output=True
                )
                if est_check.returncode != 0:
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "1", "-m", "conntrack",
                         "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                        capture_output=True
                    )

                # Loopback
                lo_check = subprocess.run(
                    ["iptables", "-C", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                    capture_output=True
                )
                if lo_check.returncode != 0:
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
                        capture_output=True
                    )

                for port in tcp_ports:
                    chk = subprocess.run(
                        ["iptables", "-C", "INPUT", "-p", "tcp",
                         "--dport", str(port), "-j", "ACCEPT"],
                        capture_output=True
                    )
                    if chk.returncode != 0:
                        subprocess.run(
                            ["iptables", "-I", "INPUT", "-p", "tcp",
                             "--dport", str(port), "-j", "ACCEPT"],
                            capture_output=True
                        )

                for port in udp_ports:
                    chk = subprocess.run(
                        ["iptables", "-C", "INPUT", "-p", "udp",
                         "--dport", str(port), "-j", "ACCEPT"],
                        capture_output=True
                    )
                    if chk.returncode != 0:
                        subprocess.run(
                            ["iptables", "-I", "INPUT", "-p", "udp",
                             "--dport", str(port), "-j", "ACCEPT"],
                            capture_output=True
                        )

                opened = sorted(set(tcp_ports + udp_ports))
                logger.info("✅ Ports opened via iptables (TCP: %s, UDP: %s)", tcp_ports, udp_ports)
                return True

            # ── 3. UFW path (active only) ────────────────────────────────────
            if ufw_active:
                for port in tcp_ports:
                    subprocess.run(["ufw", "allow", f"{port}/tcp"], capture_output=True, text=True)
                for port in udp_ports:
                    subprocess.run(["ufw", "allow", f"{port}/udp"], capture_output=True, text=True)
                opened = sorted(set(tcp_ports + udp_ports))
                logger.info("✅ Ports opened via UFW (TCP: %s, UDP: %s)", tcp_ports, udp_ports)
                return True

            logger.warning(
                "⚠️  No supported firewall tool found (nft/iptables/ufw). "
                "Management ports (TCP: %s, UDP: %s) may be inaccessible.", tcp_ports, udp_ports
            )
            return False

        except Exception as e:
            logger.error("❌ Failed to open ports: %s", e)
            return False


    def _get_required_ports(self) -> Tuple[List[int], List[int]]:
        """
        Read ALL input-direction ports from the single source of truth:
          modules/firewall/config/settings.yaml

        Returns:
          (tcp_ports, udp_ports) as sorted lists.
        """
        try:
            import yaml
            settings_path = (
                Path(__file__).resolve()
                .parent.parent.parent.parent  # enterprise_ngfw root
                / "modules" / "firewall" / "config" / "settings.yaml"
            )
            if settings_path.exists():
                with open(settings_path, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                fw = raw.get("firewall", raw)

                # Management ports (TCP)
                mgmt_tcp = [int(p) for p in fw.get("management_ports", [22, 443, 8888])]

                # Dev ports (TCP, only when enabled)
                dev_enabled = fw.get("dev_ports_enabled", True)
                dev_tcp = [int(p) for p in fw.get("dev_ports", [8000, 5173])] if dev_enabled else []

                # Custom ports — parse TCP vs UDP
                custom_tcp, custom_udp = [], []
                for cp in fw.get("custom_ports", []):
                    if cp.get("enabled", True):
                        proto = str(cp.get("protocol", "tcp")).lower()
                        direction = str(cp.get("direction", "input")).lower()
                        port = int(cp.get("port", 0))
                        if port > 0 and direction in ("input", "both"):
                            if proto in ("tcp", "both"):
                                custom_tcp.append(port)
                            if proto in ("udp", "both"):
                                custom_udp.append(port)

                tcp_ports = sorted(set(mgmt_tcp + dev_tcp + custom_tcp))
                udp_ports = sorted(set(custom_udp or [51820]))
                logger.debug("_get_required_ports: TCP=%s, UDP=%s", tcp_ports, udp_ports)
                return tcp_ports, udp_ports
        except Exception as exc:
            logger.debug("_get_required_ports: could not read settings.yaml: %s", exc)
        # Safe defaults
        return [22, 443, 8000, 5173, 8888], [51820]

    # ═══════════════════════════════════════════════════════════════
    #  Phase 6: State Management
    # ═══════════════════════════════════════════════════════════════

    def _compute_config_hash(self) -> str:
        """Create a hash of current interface config for change detection."""
        import hashlib
        config_str = json.dumps(self._interfaces_conf, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def _load_previous_state(self) -> Optional[AppliedState]:
        """Load previously applied state from disk."""
        if not STATE_FILE.exists():
            return None
        try:
            data = json.loads(STATE_FILE.read_text())
            state = AppliedState(**data)
            return state
        except Exception as e:
            logger.debug("Could not load previous state: %s", e)
            return None

    def _save_state(self):
        """Save current applied state to disk."""
        self._applied_state.timestamp = datetime.now().isoformat()
        self._applied_state.config_hash = self._compute_config_hash()
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(json.dumps(asdict(self._applied_state), indent=2))
            logger.info("💾 Network state saved to %s", STATE_FILE)
        except Exception as e:
            logger.warning("Could not save network state: %s", e)

    def _needs_reconfigure(self) -> bool:
        """Check if reconfiguration is needed (config changed or never applied)."""
        prev = self._load_previous_state()
        if not prev:
            logger.info("📋 No previous network state found — first boot configuration needed.")
            return True

        current_hash = self._compute_config_hash()
        if prev.config_hash != current_hash:
            logger.info("📋 Network config changed (hash %s → %s) — reconfiguration needed.",
                       prev.config_hash, current_hash)
            return True

        logger.info("📋 Network config unchanged since last apply. Verifying addresses...")
        return not self._verify_current_state(prev)

    def _verify_current_state(self, state: AppliedState) -> bool:
        """Verify that the previously applied state is still active on the system."""
        # Check if LAN address is still present
        if state.lan_device and state.lan_address:
            try:
                result = subprocess.run(
                    ["ip", "addr", "show", "dev", state.lan_device],
                    capture_output=True, text=True, timeout=5
                )
                addr_base = state.lan_address.split("/")[0]
                if addr_base not in result.stdout:
                    logger.info("  ⚠️  LAN address %s not found on %s — re-applying.",
                               state.lan_address, state.lan_device)
                    return False
            except Exception:
                return False

        # Check IP forwarding
        try:
            val = Path(SYSCTL_FORWARDING).read_text().strip()
            if val != "1":
                logger.info("  ⚠️  IP forwarding disabled — re-enabling.")
                return False
        except Exception:
            pass

        logger.info("  ✅ Previous network configuration verified and active.")
        return True

    # ═══════════════════════════════════════════════════════════════
    #  Master Orchestrator — Run All Phases
    # ═══════════════════════════════════════════════════════════════

    def auto_configure(self) -> bool:
        """
        Master method: runs the full auto-configuration pipeline.
        
        Returns True if all critical steps succeeded.
        """
        logger.info("=" * 70)
        logger.info("🚀 bunyanx Network Auto-Configurator Starting...")
        logger.info("=" * 70)

        # ── Phase 0: Pre-flight ──
        # FirewallPlugin (modules/firewall/engine/firewall_plugin.py) is the
        # authority for SECURITY policy rules (ACL, IPS, content filtering).
        # However, basic OS-level port accessibility for the proxy listeners
        # (port 80, 443, 8443, etc.) MUST still be guaranteed here so that
        # connections reach the proxy before any security inspection can happen.
        # Without this, the kernel DROP policy blocks all traffic before the
        # proxy can accept it, making every HTTP request time out silently.
        if not self.preflight_check():
            return False

        # Always ensure proxy listener ports are reachable at the OS level.
        # This is complementary to (not a replacement for) FirewallPlugin rules.
        self.open_management_ports()


        # ── Phase 1: Discovery ──
        logger.info("")
        logger.info("─── Phase 1: NIC Discovery ─────────────────────────")
        nics = self.discover_nics()
        if not nics:
            logger.error("❌ No physical NICs found. Cannot configure networking.")
            return False

        # ── Check if reconfiguration is needed ──
        if not self._needs_reconfigure():
            logger.info("✅ Network already configured correctly. Nothing to do.")
            logger.info("=" * 70)
            return True

        # ── Phase 2: Role Assignment ──
        logger.info("")
        logger.info("─── Phase 2: Role Assignment ───────────────────────")
        role_map = self.assign_roles()

        if not role_map:
            logger.error("❌ Could not assign any roles to NICs.")
            return False

        # Print role summary
        logger.info("")
        logger.info("┌──────────────────────────────────────────────────┐")
        logger.info("│         Network Role Assignment Summary          │")
        logger.info("├──────────┬───────────────────┬───────────────────┤")
        for role, nic in sorted(role_map.items()):
            conf = self._interfaces_conf.get(role, {})
            addr = conf.get("address", conf.get("mode", "N/A"))
            logger.info("│ %-8s │ %-17s │ %-17s │", role.upper(), nic.name, addr)
        logger.info("└──────────┴───────────────────┴───────────────────┘")

        # ── Phase 3: Apply Addresses ──
        logger.info("")
        logger.info("─── Phase 3: Applying IP Addresses ─────────────────")
        if not self.apply_addresses():
            logger.warning("⚠️  Some addresses failed to apply. Continuing anyway...")

        # ── Phase 4: Forwarding & NAT ──
        logger.info("")
        logger.info("─── Phase 4: IP Forwarding & NAT ───────────────────")
        self.enable_ip_forwarding()
        self.configure_nat()

        # ── Phase 5: Save State ──
        logger.info("")
        logger.info("─── Phase 5: Saving State ──────────────────────────")
        self._save_state()

        # ── Final Summary ──
        logger.info("")
        logger.info("=" * 70)
        logger.info("✅ Network Auto-Configuration Complete!")
        if "wan" in role_map:
            logger.info("   WAN:  %s (%s)", role_map["wan"].name,
                        self._interfaces_conf.get("wan", {}).get("mode", "dhcp"))
        if "lan" in role_map:
            logger.info("   LAN:  %s → %s", role_map["lan"].name,
                        self._interfaces_conf.get("lan", {}).get("address", "N/A"))
        if "management" in role_map:
            logger.info("   MGMT: %s → %s", role_map["management"].name,
                        self._interfaces_conf.get("management", {}).get("address", "N/A"))
        logger.info("=" * 70)

        return True

    # ═══════════════════════════════════════════════════════════════
    #  Utility: Get current state for API/Dashboard
    # ═══════════════════════════════════════════════════════════════

    def get_status(self) -> dict:
        """Return current network configuration status for API endpoints."""
        state = self._load_previous_state()
        if state:
            return {
                "configured": True,
                "timestamp": state.timestamp,
                "wan": {"device": state.wan_device, "mac": state.wan_mac, "mode": state.wan_mode},
                "lan": {"device": state.lan_device, "mac": state.lan_mac, "address": state.lan_address},
                "mgmt": {"device": state.mgmt_device, "mac": state.mgmt_mac, "address": state.mgmt_address},
                "ip_forwarding": state.ip_forwarding,
                "nat_configured": state.nat_configured,
            }
        return {"configured": False}


# ═══════════════════════════════════════════════════════════════════
#  Standalone Execution (for testing / manual runs)
# ═══════════════════════════════════════════════════════════════════

def run_auto_config(config: dict) -> bool:
    """Convenience function to run auto-config from any module."""
    configurator = NetworkAutoConfigurator(config)
    return configurator.auto_configure()


if __name__ == "__main__":
    import yaml
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)8s] %(name)s: %(message)s"
    )
    
    # Load config
    config_path = Path(__file__).resolve().parent.parent.parent / "config" / "base.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        
        configurator = NetworkAutoConfigurator(config)
        success = configurator.auto_configure()
        sys.exit(0 if success else 1)
    else:
        print(f"Config not found: {config_path}")
        sys.exit(1)
