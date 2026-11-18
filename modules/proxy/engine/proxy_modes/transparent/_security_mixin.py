#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security policy mixin — domain/IP blacklist checks.

Consumed by MITMProxy via multiple inheritance (SecurityMixin).
Depends only on self.security_config and self.ebpf_manager which are
initialized in MITMProxy.__init__.
"""
import asyncio
import fnmatch
import logging

logger = logging.getLogger(__name__)


class SecurityMixin:
    """Security policy enforcement methods for MITMProxy."""

    def _check_security_policy(self, client_ip: str, target_host: str) -> bool:
        """
        Check if connection is allowed by security policies.

        Args:
            client_ip:   Client IP address
            target_host: Target hostname

        Returns:
            True if allowed, False if blocked
        """
        # Check IP blacklist
        blacklist_ips = self.security_config.get('blacklist_ips', [])
        if client_ip in blacklist_ips:
            logger.warning(f"Blocked blacklisted IP: {client_ip}")
            return False

        # Check domain blacklist
        blacklist_domains = self.security_config.get('blacklist_domains', [])
        for pattern in blacklist_domains:
            if self._match_domain_pattern(target_host, pattern):
                logger.warning(f"Blocked blacklisted domain: {target_host}")
                if self.ebpf_manager:
                    asyncio.create_task(
                        self.ebpf_manager.add_blocked_domain(target_host)
                    )
                return False

        return True

    def _match_domain_pattern(self, domain: str, pattern: str) -> bool:
        """Match domain against pattern (supports wildcards) — ReDoS safe."""
        return fnmatch.fnmatch(domain.lower(), pattern.lower())
