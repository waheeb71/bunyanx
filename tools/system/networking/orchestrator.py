import logging
from typing import Dict, List, Any
import os

from system.networking.appliance.netfilter_manager import NetfilterManager
from system.core.framework.plugin_base import InspectorPlugin

logger = logging.getLogger(__name__)

class NetworkRuleOrchestrator:
    """
    Central orchestrator for OS-level network rules.
    Aggregates rules from all loaded security modules and injects them 
    into the NetfilterManager. This guarantees that the core system 
    remains unaware of specific module implementations (e.g. proxy logic, 
    firewall policies, DNS intercepts).
    """

    def __init__(self, config: dict):
        self.config = config
        # ── Resolve management interface dynamically ──────────────────────────
        # Never hardcode 'eth0' — actual interface name depends on hardware.
        # InterfaceManager reads from /etc/bunyanx/interfaces_applied.yaml
        # (written by network_auto_configurator). If unavailable, pass None so
        # NetfilterManager applies MGMT protection without an iifname filter.
        mgmt_iface = None
        try:
            from system.networking.appliance.interface_manager import InterfaceManager
            iface_mgr  = InterfaceManager(self.config)
            mgmt_iface = iface_mgr.get_role_device("management")
            if mgmt_iface:
                logger.info("NetworkRuleOrchestrator: mgmt interface = %s", mgmt_iface)
            else:
                logger.info(
                    "NetworkRuleOrchestrator: no 'management' role found — "
                    "MGMT protection will apply to all interfaces"
                )
        except Exception as exc:
            logger.warning("NetworkRuleOrchestrator: InterfaceManager unavailable: %s", exc)

        self.netfilter = NetfilterManager(
            config=self.config,
            mgmt_interface_name=mgmt_iface,
        )


    def orchestrate_rules(self, rule_providers: List[Any]):
        """
        Gathers nftables rules from all rule providers and applies them atomically.
        """
        if os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() != 0):
            logger.warning("Skipping NetworkRuleOrchestrator rule injection due to lack of root privileges (Windows or non-root POSIX).")
            return

        logger.info("Orchestrating module-specific network rules...")

        # Start with a clean slate (drop policies, empty chains)
        self.netfilter.clear_rules()

        # Aggregate rules by chain
        aggregated_rules: Dict[str, List[str]] = {
            'prerouting': [],
            'input': [],
            'forward': [],
            'postrouting': []
        }

        for provider in rule_providers:
            if getattr(provider, 'enabled', False) == False:
                continue

            try:
                module_rules = provider.get_netfilter_rules()
                if not module_rules:
                    continue

                provider_name = getattr(provider, 'name', provider.__class__.__name__)
                logger.debug(f"Gathering network rules from provider: {provider_name}")

                for chain, rules in module_rules.items():
                    chain_lower = chain.lower()
                    if chain_lower in aggregated_rules and isinstance(rules, list):
                        aggregated_rules[chain_lower].extend(rules)
            except Exception as e:
                provider_name = getattr(provider, 'name', provider.__class__.__name__)
                logger.error(f"Error gathering rules from {provider_name}: {e}")

        # Inject aggregated rules into NetfilterManager
        for chain, rules in aggregated_rules.items():
            if rules:
                self.netfilter.inject_rules(chain, rules)

        # ── CRITICAL: inject MGMT protection LAST, before apply_atomic ──────────
        # Must happen after clear_rules() + inject_rules() so the MGMT whitelist
        # rules are always at the TOP of the input chain and never flushed away.
        # This is why "ports open in logs but actually closed" happened before:
        # open_management_ports() ran first, then clear_rules() wiped everything.
        self.netfilter.add_mgmt_protection_rules()

        # Apply atomically to the OS
        if self.netfilter.apply_atomic():
            logger.info("✅ nftables network rules built and applied atomically by orchestrator.")
        else:
            logger.error("❌ Failed to apply netfilter rules.")

