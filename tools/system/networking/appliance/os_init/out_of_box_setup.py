#!/usr/env/bin python3
"""
Enterprise bunyanx - Out Of Box Experience (OOBE) Network Setup
==================================================================
Runs on system initialization. Checks if the configuration has any
networking configured. If no MGMT interface is found (e.g., first boot),
it scans physical interfaces, picks the first active one, maps its MAC Address,
and safely declares it as the Management Interface (MGMT) locked at 10.10.0.1.
"""

import sys
import logging
from pathlib import Path

# Add project root to path if running standalone
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent.parent))

from system.config.config_manager import ConfigManager

logger = logging.getLogger("OOBENetworkSetup")
logging.basicConfig(level=logging.INFO)

def get_physical_macs():
    import psutil
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    
    mac_map = {}
    for nic, addrs_list in addrs.items():
        if nic == "lo" or "docker" in nic or "veth" in nic:
            continue
            
        mac = None
        for addr in addrs_list:
            if addr.family == psutil.AF_LINK:
                mac = addr.address
                
        is_up = stats[nic].isup if nic in stats else False
        if mac:
            mac_map[nic] = {"mac": mac.upper(), "is_up": is_up}
            
    return mac_map

def setup_oobe_mgmt():
    cfg = ConfigManager.instance()
    
    # Check if we already have a MGMT interface configured by MAC
    mgmt_mac = cfg.get("interfaces.management.mac")
    if mgmt_mac:
        logger.info(f"OOBE Check: Management MAC already configured ({mgmt_mac}). Skipping.")
        return
        
    logger.info("OOBE Check: No Management interface configured. Scanning physical cards...")
    
    macs = get_physical_macs()
    if not macs:
        logger.error("OOBE Error: No physical network cards found! Cannot assign MGMT.")
        return
        
    # Pick the first active link, fallback to just the first alphabetically
    chosen_nic = None
    for nic, info in macs.items():
        if info["is_up"]:
            chosen_nic = nic
            break
            
    if not chosen_nic:
        chosen_nic = sorted(list(macs.keys()))[0]
        
    chosen_mac = macs[chosen_nic]["mac"]
    logger.info(f"OOBE: Selecting {chosen_nic} (MAC: {chosen_mac}) as emergency MGMT port.")
    
    # We must patch the base.yaml config
    current_interfaces = cfg.get("interfaces", {})
    if not isinstance(current_interfaces, dict):
        current_interfaces = {}
        
    current_interfaces["management"] = {
        "mac": chosen_mac,
        "address": "10.10.0.1/24",
        "locked": True,
        "fail_safe": True
    }
    
    # To truly keep it persistent, we write to base.yaml directly here since ConfigManager
    # might not have a direct "write to base.yaml" abstract method for specific keys yet.
    # We will load, patch, and dump.
    import yaml
    base_yaml_path = Path(__file__).resolve().parent.parent.parent.parent / "config" / "base.yaml"
    
    try:
        with open(base_yaml_path, "r", encoding="utf-8") as f:
            base_data = yaml.safe_load(f) or {}
            
        base_data["interfaces"] = current_interfaces
        
        with open(base_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(base_data, f, default_flow_style=False, sort_keys=False)
            
        logger.info(f"✅ OOBE: Successfully locked MAC {chosen_mac} as MGMT in base.yaml.")
        # Reload live config
        cfg.force_reload()
        
    except Exception as e:
        logger.error(f"Failed to write OOBE config to {base_yaml_path}: {e}")

if __name__ == "__main__":
    setup_oobe_mgmt()
