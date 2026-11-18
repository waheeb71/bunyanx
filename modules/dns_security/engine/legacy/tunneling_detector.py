import logging

logger = logging.getLogger(__name__)

class DNSTunnelingDetector:
    """ Detects DNS tunneling (e.g., iodine, dnscat2) by analyzing query lengths and types """

    # BUG-1 FIX: These constants are now DEFAULTS only.
    # The actual threshold is read from DNSEngine.tunneling_query_threshold
    # via the caller (plugin.py) and passed in as max_total_length.
    # Keeping defaults here so the class can still be used standalone.
    MAX_SUBDOMAIN_LENGTH = 50
    MAX_TOTAL_LENGTH = 150
    SUSPICIOUS_TYPES = ['TXT', 'NULL', 'SRV', 'MX']

    @staticmethod
    def _mask_domain(domain: str) -> str:
        """SEC-9 FIX: Mask domain labels to prevent exfiltrated data appearing in SIEM logs.
        Shows only the TLD and last label; all subdomains are replaced with '[MASKED]'.
        Example: 'exfil-data.evil.example.com' -> '[MASKED].example.com'
        """
        parts = domain.split(".")
        if len(parts) <= 2:
            return domain  # e.g. 'evil.com' — safe to log as-is
        return "[MASKED]." + ".".join(parts[-2:])

    @classmethod
    def is_tunneling(
        cls,
        domain: str,
        query_type: str = 'A',
        max_total_length: int = None,     # BUG-1 FIX: accept config-driven threshold
        max_subdomain_length: int = None,  # optional: also configurable
    ) -> bool:
        """ Returns True if the DNS query exhibits tunneling characteristics.

        Args:
            domain: Full DNS domain name to inspect.
            query_type: DNS query type string (A, TXT, NULL, etc.)
            max_total_length: Override MAX_TOTAL_LENGTH from module config.
                              If None, uses class default (150).
            max_subdomain_length: Override MAX_SUBDOMAIN_LENGTH. Defaults to 50.
        """
        _max_total = max_total_length if max_total_length is not None else cls.MAX_TOTAL_LENGTH
        _max_sub   = max_subdomain_length if max_subdomain_length is not None else cls.MAX_SUBDOMAIN_LENGTH

        safe_domain = cls._mask_domain(domain)  # SEC-9: masked version for logging

        if query_type.upper() in cls.SUSPICIOUS_TYPES and len(domain) > 60:
            logger.info(f"DNS Tunneling (Suspicious Type/Length): {safe_domain} [{query_type}]")
            return True

        if len(domain) > _max_total:
            logger.info(f"DNS Tunneling (Total Length): length {len(domain)} > {_max_total} in {safe_domain}")
            return True

        labels = domain.split('.')
        for label in labels:
            if len(label) > _max_sub:
                logger.debug(
                    f"DNS Tunneling (Label Length): label is {len(label)} chars in {safe_domain}"
                )
                return True

        return False
