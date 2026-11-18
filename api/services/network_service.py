"""
Enterprise bunyanx - Network Service Layer
===================================================
Contains business logic for networking and interface assignments.
"""
import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Singleton managers (lazy-initialized)
_interface_manager = None

def load_config() -> dict:
    import yaml
    config_path = Path(__file__).parent.parent.parent / "system" / "config" / "base.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def get_interface_manager():
    """Lazy singleton for InterfaceManager."""
    global _interface_manager
    if _interface_manager is None:
        from system.networking.appliance.interface_manager import InterfaceManager
        config = load_config()
        _interface_manager = InterfaceManager(config)
    return _interface_manager

async def get_all_interfaces() -> list:
    """Returns all physical NICs discovered on this appliance."""
    mgr = get_interface_manager()
    return mgr.get_all_nics_with_roles()

async def assign_interfaces_roles(assignments: list) -> dict:
    """
    Assigns roles to physical NICs by MAC address.
    Triggers a 30-second rollback timer.
    """
    config = load_config()
    mgr = get_interface_manager()

    current_interfaces = config.get("interfaces", {})
    new_interfaces = {"management": current_interfaces.get("management", {})}

    for assignment in assignments:
        role = assignment.role.lower()

        if role == "management":
            raise ValueError("The management interface is locked and cannot be changed via API.")

        if role not in ["wan", "lan", "dmz", "unassigned"]:
            raise ValueError(f"Invalid role provided: '{role}'. Only 'wan', 'lan', 'dmz', or 'unassigned' are allowed.")

        if role == "unassigned":
            continue

        new_interfaces[role] = {
            "mac": assignment.mac.upper(),
            "mode": assignment.mode or "dhcp",
        }
        if assignment.mode == "static" and assignment.address:
            new_interfaces[role]["address"] = assignment.address
        if assignment.gateway:
            new_interfaces[role]["gateway"] = assignment.gateway
        if assignment.dns:
            new_interfaces[role]["dns"] = assignment.dns

    success = mgr.apply_with_safety(new_interfaces)
    if not success:
        raise RuntimeError("Failed to apply interface configuration.")

    return {
        "status": "pending_confirm",
        "message": "Configuration applied. Send POST /confirm within 30 seconds to lock in, or it will auto-rollback.",
        "timeout_seconds": 30
    }

async def confirm_changes() -> dict:
    """Confirms and commits the pending network configuration change."""
    mgr = get_interface_manager()
    return mgr.confirm()

async def get_networking_status() -> dict:
    """Return current nftables status and active interface roles."""
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True, text=True
        )
        nft_active = result.returncode == 0

        mgr = get_interface_manager()
        nics = mgr.get_all_nics_with_roles()

        return {
            "nftables_active": nft_active,
            "nftables_ruleset": result.stdout[:2000] if nft_active else None,
            "interfaces": nics,
        }
    except FileNotFoundError:
        return {"nftables_active": False, "note": "nft not available on this platform"}

async def toggle_transparent_proxy_mode(enable: bool) -> dict:
    """Enable or disable transparent proxy rules (nftables NAT)."""
    from system.networking.orchestrator import NetworkRuleOrchestrator
    from modules.proxy.engine.transparent_proxy import TransparentProxyManager
    config = load_config()

    orchestrator = NetworkRuleOrchestrator(config)
    orchestrator.netfilter.enable_ip_forwarding()

    if enable:
        proxy_mgr = TransparentProxyManager(config)
        orchestrator.orchestrate_rules([proxy_mgr])
        msg = "Transparent proxy ENABLED (nftables NAT rules applied)."
    else:
        # Revert to a safe baseline with only management ports allowed
        orchestrator.netfilter.clear_rules()
        orchestrator.netfilter.add_mgmt_protection_rules()
        orchestrator.netfilter.apply_atomic()
        msg = "Transparent proxy DISABLED (Safe mode baseline restored)."

    return {"status": "success", "message": msg}
