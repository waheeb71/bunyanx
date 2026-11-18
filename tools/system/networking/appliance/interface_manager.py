#!/usr/bin/env python3
"""
Enterprise bunyanx - Hardware Interface Manager
===================================================
Single Source of Truth for all physical NIC management.

Responsibilities:
  1. Discover physical NICs and their MAC addresses.
  2. Map logical roles (MGMT, WAN, LAN, DMZ) to MACs.
  3. Generate systemd-networkd .network files from config.
  4. Apply network changes with Hybrid Rollback Safety:
       - 30-second timeout timer
       - Parallel health checks (carrier + ping gateway)
       - Auto-rollback if health check fails OR UI doesn't confirm
  5. Track boot success/failure counter.
"""

import os
import subprocess
import threading
import logging
import time
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

NETWORKD_DIR = Path("/etc/systemd/network")
bunyanx_CONF_FILE = Path("/etc/bunyanx/interfaces_applied.yaml")
BOOT_COUNTER_FILE = Path("/etc/bunyanx/boot_counter")
ROLLBACK_TIMEOUT_SECONDS = 30
class NICInfo:
    """Represents a single physical network interface."""

    def __init__(self, name: str, mac: str, is_up: bool, speed_mbps: int = 0):
        self.name = name
        self.mac = mac.upper()
        self.is_up = is_up
        self.speed_mbps = speed_mbps

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mac": self.mac,
            "is_up": self.is_up,
            "speed_mbps": self.speed_mbps,
        }

class InterfaceManager:
    """
    Manages physical NICs for the bunyanx Hardware Appliance.
    Uses MAC Address as the primary identifier (never interface names).
    """

    # Roles that are considered data-plane (can be re-assigned via UI)
    CONFIGURABLE_ROLES = {"wan", "lan", "dmz"}
    # Roles that are locked and cannot be changed via UI
    PROTECTED_ROLES = {"management"}

    def __init__(self, config: dict):
        self.config = config
        self._interfaces_conf: dict = config.get("interfaces", {})
        self._rollback_timer: Optional[threading.Timer] = None
        self._pre_change_snapshot: Optional[list] = None  # list of (filename, content)
        self._confirm_event = threading.Event()

    # ─────────────────────────────────────────────────────────
    # Discovery
    # ─────────────────────────────────────────────────────────

    def discover_nics(self) -> list[NICInfo]:
        """Scan /sys/class/net for physical NICs. Returns list of NICInfo."""
        nics = []
        sys_net = Path("/sys/class/net")
        if not sys_net.exists():
            logger.warning("Not on Linux — interface discovery unavailable.")
            return nics

        for nic_path in sys_net.iterdir():
            nic_name = nic_path.name
            # Skip loopback and virtual interfaces
            if nic_name in ("lo",) or nic_name.startswith(("docker", "veth", "br-", "virbr", "wg")):
                continue

            try:
                mac_file = nic_path / "address"
                mac = mac_file.read_text().strip().upper() if mac_file.exists() else "00:00:00:00:00:00"

                operstate_file = nic_path / "operstate"
                is_up = (operstate_file.read_text().strip() == "up") if operstate_file.exists() else False

                speed_file = nic_path / "speed"
                speed = 0
                if speed_file.exists():
                    try:
                        speed = int(speed_file.read_text().strip())
                    except ValueError:
                        pass

                nics.append(NICInfo(nic_name, mac, is_up, speed))
            except Exception as e:
                logger.debug(f"Could not read NIC info for {nic_name}: {e}")

        return nics

    def get_nic_by_mac(self, mac: str) -> Optional[NICInfo]:
        """Resolve a MAC address to its current kernel interface name."""
        target = mac.upper()
        for nic in self.discover_nics():
            if nic.mac == target:
                return nic
        return None

    def get_role_device(self, role: str) -> Optional[str]:
        """
        Returns the current kernel device name for a given role (e.g. 'wan').
        Resolves via MAC address.
        """
        role_conf = self._interfaces_conf.get(role, {})
        mac = role_conf.get("mac")
        if not mac:
            return None
        nic = self.get_nic_by_mac(mac)
        return nic.name if nic else None

    # ─────────────────────────────────────────────────────────
    # systemd-networkd File Generator
    # ─────────────────────────────────────────────────────────

    def _generate_networkd_file(self, role: str, role_conf: dict) -> Optional[tuple]:
        """
        Build a systemd-networkd .network file content from a role config.
        Returns (filename, content) or None.
        """
        mac = role_conf.get("mac")
        if not mac:
            return None

        lines = ["[Match]", f"MACAddress={mac}", "", "[Network]"]

        if role == "management":
            address = role_conf.get("address", "10.10.0.1/24")
            lines.append(f"Address={address}")
            lines.append("DHCP=no")

        elif role_conf.get("mode") == "dhcp":
            lines.append("DHCP=yes")

        else:
            import re
            
            address = role_conf.get("address")
            if address:
                # Sanitize to prevent CRLF injection
                address = re.sub(r'[\r\n\s]', '', str(address))
                lines.append(f"Address={address}")
            gateway = role_conf.get("gateway")
            if gateway:
                # Sanitize to prevent CRLF injection
                gateway = re.sub(r'[\r\n\s]', '', str(gateway))
                lines.append(f"Gateway={gateway}")
            dns = role_conf.get("dns", "1.1.1.1")
            # Sanitize to prevent CRLF injection
            dns = re.sub(r'[\r\n\s]', '', str(dns))
            lines.append(f"DNS={dns}")
            lines.append("DHCP=no")

        # Priority prefix: 10 = management (first), 20 = wan, 30 = lan, 40 = dmz
        prefix_map = {"management": "10", "wan": "20", "lan": "30", "dmz": "40"}
        prefix = prefix_map.get(role, "50")
        filename = f"{prefix}-bunyanx-{role}.network"
        content = "\n".join(lines) + "\n"
        return (filename, content)

    def _write_networkd_files(self, interfaces_conf: dict) -> list:
        """Write all .network files; returns list of (filename, content) for rollback."""
        written = []
        NETWORKD_DIR.mkdir(parents=True, exist_ok=True)

        for role, role_conf in interfaces_conf.items():
            result = self._generate_networkd_file(role, role_conf)
            if result:
                filename, content = result
                filepath = NETWORKD_DIR / filename
                filepath.write_text(content)
                written.append((str(filepath), content))
                logger.debug(f"Written: {filepath}")

        return written
    def _snapshot_networkd_files(self) -> list:
        """Save current .network files for rollback."""
        snapshot = []
        if NETWORKD_DIR.exists():
            for f in NETWORKD_DIR.glob("*-bunyanx-*.network"):
                snapshot.append((str(f), f.read_text()))
        return snapshot

    def _restore_snapshot(self, snapshot: list):
        """Restore .network files from a snapshot."""
        # Remove current bunyanx managed files
        if NETWORKD_DIR.exists():
            for f in NETWORKD_DIR.glob("*-bunyanx-*.network"):
                f.unlink(missing_ok=True)

        # Restore snapshot files
        for filepath, content in snapshot:
            Path(filepath).write_text(content)

        self._restart_networkd()
        logger.info("✅ Rollback complete: previous network config restored.")

    @staticmethod
    def _restart_networkd():
        try:
            subprocess.run(["networkctl", "reload"], check=True, capture_output=True, timeout=15)
        except Exception as e:
            logger.error(f"Failed to reload networkd: {e}")

    # ─────────────────────────────────────────────────────────
    # Health Check Engine
    # ─────────────────────────────────────────────────────────

    def _check_mgmt_carrier(self) -> bool:
        """Check MGMT interface has link carrier (hardware signal)."""
        mgmt_conf = self._interfaces_conf.get("management", {})
        mac = mgmt_conf.get("mac")
        if not mac:
            return True  # Can't verify — assume OK
        nic = self.get_nic_by_mac(mac)
        if not nic:
            logger.warning("MGMT NIC not found during health check.")
            return False
        return nic.is_up

    def _check_wan_gateway_reachable(self) -> bool:
        """Ping the configured WAN gateway to verify outside connectivity."""
        wan_conf = self._interfaces_conf.get("wan", {})
        gateway = wan_conf.get("gateway")
        if not gateway:
            return True  # No gateway configured — skip check
        try:
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "3", gateway],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def _run_health_checks(self) -> bool:
        """Run all health checks. Returns True if network is healthy."""
        carrier_ok = self._check_mgmt_carrier()
        logger.info(f"Health Check — MGMT Carrier: {'✅' if carrier_ok else '❌'}")

        gateway_ok = self._check_wan_gateway_reachable()
        logger.info(f"Health Check — WAN Gateway: {'✅' if gateway_ok else '❌ (might be OK if WAN not assigned)'}")

        return carrier_ok  # Gateway check is advisory only

    # ─────────────────────────────────────────────────────────
    # Hybrid Rollback Engine
    # ─────────────────────────────────────────────────────────

    def _rollback_due_to_timeout(self):
        """Called by timer thread when no confirm received in time."""
        if self._confirm_event.is_set():
            return  # Already confirmed — no action needed

        logger.warning(f"⏱️  Rollback triggered: no confirm received in {ROLLBACK_TIMEOUT_SECONDS}s.")
        if self._pre_change_snapshot is not None:
            self._restore_snapshot(self._pre_change_snapshot)

    def apply_with_safety(self, new_interfaces_conf: dict) -> bool:
        """
        Apply new interface config with Hybrid Rollback protection:
         1. Snapshot current state.
         2. Write new .network files.
         3. Restart networkd.
         4. Start 30s timer + health check thread.
         5. If health check fails OR timer expires without confirm → rollback.

        Returns True if apply was successful (requires subsequent confirm()).
        """
        if os.name != "posix":
            logger.warning("Not running on Linux. Simulating apply.")
            self._interfaces_conf = new_interfaces_conf
            return True

        logger.info("Snapshotting current network config...")
        self._pre_change_snapshot = self._snapshot_networkd_files()
        self._confirm_event.clear()

        try:
            logger.info("Writing new systemd-networkd config files...")
            self._write_networkd_files(new_interfaces_conf)
            self._restart_networkd()
        except Exception as e:
            logger.error(f"Failed to write/apply networkd files: {e}. Auto-rolling back.")
            if self._pre_change_snapshot:
                self._restore_snapshot(self._pre_change_snapshot)
            return False

        # Update in-memory state
        self._interfaces_conf = new_interfaces_conf

        # Run health checks in background
        def _health_worker():
            time.sleep(5)  # Give networkd a moment to settle
            if not self._run_health_checks():
                logger.warning("Health check FAILED. Triggering immediate rollback.")
                self._confirm_event.set()  # Stop the timer
                if self._pre_change_snapshot:
                    self._restore_snapshot(self._pre_change_snapshot)

        threading.Thread(target=_health_worker, daemon=True, name="HW-HealthCheck").start()

        # Start rollback timer
        self._rollback_timer = threading.Timer(
            ROLLBACK_TIMEOUT_SECONDS,
            self._rollback_due_to_timeout
        )
        self._rollback_timer.daemon = True
        self._rollback_timer.start()

        logger.info(f"⏳ Network applied. Waiting for UI confirm within {ROLLBACK_TIMEOUT_SECONDS}s...")
        return True

    def confirm(self) -> dict:
        """
        Called when UI sends the /confirm request.
        Cancels the rollback timer and marks the boot as successful.
        """
        if self._rollback_timer:
            self._rollback_timer.cancel()
        self._confirm_event.set()

        # Reset boot failure counter on successful apply
        BOOT_COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
        BOOT_COUNTER_FILE.write_text("0")

        logger.info("✅ Network change CONFIRMED by UI. Rollback timer cancelled.")
        return {"status": "confirmed", "message": "Network configuration saved and active."}

    # ─────────────────────────────────────────────────────────
    # Public API helpers
    # ─────────────────────────────────────────────────────────

    def get_all_nics_with_roles(self) -> list:
        """
        Returns all discovered NICs enriched with their current assigned role.
        Used by API → GET /interfaces
        """
        nics = self.discover_nics()
        role_by_mac = {}
        for role, role_conf in self._interfaces_conf.items():
            mac = (role_conf.get("mac") or "").upper()
            if mac:
                role_by_mac[mac] = role

        result = []
        for nic in nics:
            info = nic.to_dict()
            info["role"] = role_by_mac.get(nic.mac, "unassigned")
            info["locked"] = (info["role"] == "management")
            result.append(info)

        return result
