#!/usr/bin/env python3
"""
Enterprise bunyanx - Dynamic Transparent Proxy Configuration Manager
Replaces legacy iptables logic with NetfilterManager (nftables).
Reads from InterfaceManager mapping logic directly.
"""

import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class TransparentProxyManager:
    """
    Provides OS-level network rules for transparent interception.
    These rules are injected by the NetworkRuleOrchestrator.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.proxy_config = self.config.get("proxy", {})
        self.routing_config = self.config.get("routing", {})

        self.https_redirect_port = 8443
        self.http_redirect_port  = 8080
        self.dns_intercept_port  = (
            self.config.get('modules', {})
                       .get('dns_security', {})
                       .get('intercept_port', 5353)
        )

        from system.networking.appliance.interface_manager import InterfaceManager
        iface_mgr = InterfaceManager(self.config)

        self.wan_interfaces: List[str] = []
        wan_dev = iface_mgr.get_role_device("wan")
        if wan_dev:
            self.wan_interfaces.append(wan_dev)

        self.lan_interfaces: List[str] = []
        lan_dev = iface_mgr.get_role_device("lan")
        if lan_dev:
            self.lan_interfaces.append(lan_dev)

        self.mgmt_interface = iface_mgr.get_role_device("management")
        self.enabled = True
        self.name = "TransparentProxyManager"

        # VIPs: external_ip:external_port → internal_ip:internal_port
        self.vips: List[Dict[str, Any]] = self.proxy_config.get("vips", [])

    def get_netfilter_rules(self) -> Dict[str, List[str]]:
        """
        Returns nftables rules required to:
        1. DNAT inbound WAN traffic to VIPs (reverse proxy) — FIRST priority
        2. Intercept outbound LAN web/DNS traffic (transparent forward proxy)
        3. Masquerade forwarded traffic
        4. Allow redirected ports in INPUT chain

        These are aggregated by the NetworkRuleOrchestrator.
        """
        rules = {
            'prerouting':  [],
            'input':       [],
            'forward':     [],
            'postrouting': [],
        }

        rules['prerouting'].append("# [TRANSPARENT PROXY PREROUTING]")
        # Skip link-local, multicast, loopback (IPv4 & IPv6) — never proxy these
        rules['prerouting'].append("ip daddr { 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 } return")
        rules['prerouting'].append("ip6 daddr { ::1/128, fe80::/10, ff00::/8 } return")

        # ── [1] VIP rules: WAN → internal servers ─────────────────────────────
        # Two modes are supported per VIP (configured via the "mode" field):
        #
        #   mode: proxy  (default) — redirect to local application proxy (:8080).
        #                            Traffic passes through WAF / DLP / TLS
        #                            inspection pipeline before reaching the backend.
        #
        #   mode: dnat             — kernel-level DNAT directly to internal_ip:port.
        #                            ⚠️  BYPASSES WAF / DLP / TLS inspection entirely.
        #                            Use only for non-HTTP protocols (e.g. FTP, SMTP
        #                            raw) where application-layer inspection is not
        #                            required or not possible.
        #
        # All VIP rules MUST come BEFORE the skuid=0 return rule so that
        # proxy-generated traffic is never re-intercepted.
        if self.vips:
            rules['prerouting'].append("# [VIP rules — proxy-redirect and kernel-DNAT — evaluated before skuid]")
            for vip in self.vips:
                ext_ip   = vip.get("external_ip", "")
                ext_port = vip.get("external_port", 80)
                name     = vip.get("name", "VIP")
                mode     = vip.get("mode", "proxy")   # default: proxy (backward-compatible)

                if not ext_ip:
                    continue

                if mode == "proxy":
                    # ── Application proxy: redirect to local proxy port ────────
                    redirect_port = self.http_redirect_port
                    for wan_iface in self.wan_interfaces:
                        rules['prerouting'].append(
                            f"# VIP (proxy): {name} ({ext_ip}:{ext_port} → proxy:{redirect_port})"
                        )
                        rules['prerouting'].append(
                            f'iifname "{wan_iface}" '
                            f'ip daddr {ext_ip} tcp dport {ext_port} '
                            f'redirect to :{redirect_port}'
                        )

                elif mode == "dnat":
                    # ── Kernel DNAT: bypass proxy, forward directly to backend ──
                    # ⚠️  WAF / DLP / TLS inspection is NOT applied in this path.
                    int_ip   = vip.get("internal_ip", "")
                    int_port = vip.get("internal_port", ext_port)

                    if not int_ip:
                        logger.warning(
                            "VIP '%s' has mode=dnat but no internal_ip — skipping rule generation.",
                            name,
                        )
                        continue

                    for wan_iface in self.wan_interfaces:
                        rules['prerouting'].append(
                            f"# VIP (dnat): {name} ({ext_ip}:{ext_port} → {int_ip}:{int_port})"
                            f"  ⚠️ bypasses application proxy inspection"
                        )
                        rules['prerouting'].append(
                            f'iifname "{wan_iface}" '
                            f'ip daddr {ext_ip} tcp dport {ext_port} '
                            f'dnat to {int_ip}:{int_port}'
                        )

                else:
                    # ── Unknown mode: fail-safe, emit warning, skip rule ───────
                    logger.warning(
                        "VIP '%s' has unknown mode '%s'; skipping rule generation. "
                        "Valid values are: 'proxy' (default), 'dnat'.",
                        name,
                        mode,
                    )

        # ── [2] Transparent forward proxy: LAN → internet ─────────────────────
        rules['prerouting'].append("# Skip proxy-generated traffic (no redirect loop)")
        rules['prerouting'].append("meta skuid 0 return")

        for iface in self.lan_interfaces:
            rules['prerouting'].extend([
                f"# LAN {iface}: redirect HTTP/HTTPS/DNS to proxy (IPv4 & IPv6)",
                f'iifname "{iface}" tcp dport 80  redirect to :{self.http_redirect_port}',
                f'iifname "{iface}" tcp dport 443 redirect to :{self.https_redirect_port}',
                f'iifname "{iface}" udp dport 53  redirect to :{self.dns_intercept_port}',
            ])

        # ── [3] WAN masquerade (postrouting) ──────────────────────────────────
        for wan_iface in self.wan_interfaces:
            rules['postrouting'].append(f'# NAT masquerade on {wan_iface}')
            rules['postrouting'].append(f'oifname "{wan_iface}" masquerade')

        # ── [4] INPUT: allow redirected proxy traffic ──────────────────────────
        rules['input'].append("# Allow transparent proxy redirected traffic")
        rules['input'].append(
            f"tcp dport {{ {self.http_redirect_port}, {self.https_redirect_port} }} accept"
        )
        rules['input'].append(
            f"udp dport {self.dns_intercept_port} accept"
        )

        return rules

