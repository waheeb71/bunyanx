"""
system/events/topics.py
========================
bunyanx NGFW — Event Bus Topic Registry
==========================================

Single source of truth for all event topic strings.
Import only this file to avoid topic name typos.

Architecture (Phase 5)
-----------------------
This file defines **framework-level** topics that cross module boundaries
(data plane, system health, SIEM, correlation, etc.).

Module-specific topics are defined in ``<module>/events/topics.py`` in each
module and registered here at startup via ``Topics.register()``.

Usage::

    # System code:
    from system.events.topics import Topics
    bus.publish(Topics.THREAT_DETECTED, payload)

    # Module code (define local topics + register):
    from system.events.topics import Topics
    bus.publish(Topics.IDS_PORT_SCAN, payload)

    # Module registering its own topics at init time (optional):
    Topics.register('MY_MODULE_EVENT', 'my_module.custom_event')
"""


class _TopicsMeta(type):
    """
    Metaclass that allows Topics to act as a class with dynamic registration.
    Topics.register('NAME', 'namespace.event') adds NAME to the class at runtime.
    """

    def register(cls, attribute: str, value: str) -> None:
        """
        Register a new topic at runtime.

        Args:
            attribute:  Python attribute name, e.g. ``IDS_PORT_SCAN``
            value:      Event bus topic string, e.g. ``"ids.port_scan"``

        Raises:
            ValueError: If *attribute* is already registered with a **different** value.
        """
        existing = getattr(cls, attribute, None)
        if existing is not None and existing != value:
            raise ValueError(
                f"[Topics] Conflict: '{attribute}' already registered as '{existing}' "
                f"(cannot override with '{value}')"
            )
        setattr(cls, attribute, value)

    def all_topics(cls) -> dict:
        """Return {attribute: value} for every registered topic."""
        return {
            k: v for k, v in vars(cls).items()
            if not k.startswith('_') and isinstance(v, str)
        }


class Topics(metaclass=_TopicsMeta):
    """All event bus topic names — framework and module-registered."""

    # ── Data Plane ──────────────────────────────────────────────────
    PACKET_RECEIVED        = "packet.received"
    PACKET_INSPECTED       = "packet.inspected"
    CONNECTION_ESTABLISHED = "connection.established"
    CONNECTION_CLOSED      = "connection.closed"
    FLOW_CREATED           = "flow.created"

    # ── Security Events ─────────────────────────────────────────────
    THREAT_DETECTED        = "threat.detected"
    POLICY_EVALUATED       = "policy.evaluated"
    ANOMALY_SCORED         = "anomaly.scored"

    # ── AI Engine ───────────────────────────────────────────────────
    AI_SCORE_REQUESTED     = "ai.score_requested"
    AI_SCORE_GENERATED     = "ai.score_generated"

    # ── Response / Enforcement ─────────────────────────────────────
    RESPONSE_BLOCK         = "response.block"
    RESPONSE_QUARANTINE    = "response.quarantine"
    RESPONSE_ALERT         = "response.alert"

    # ── System Health ───────────────────────────────────────────────
    MODULE_HEALTH          = "module.health"
    MODULE_STARTED         = "module.started"
    MODULE_STOPPED         = "module.stopped"

    # ── Intelligence ────────────────────────────────────────────────
    INTEL_UPDATED          = "intel.updated"
    CORRELATION_TRIGGERED  = "correlation.triggered"

    # ── Config / Feature Flags ──────────────────────────────────────
    CONFIG_RELOADED        = "config.reloaded"
    CONFIG_SAVED           = "config.saved"
    FEATURE_CHANGED        = "feature.changed"

    # ── System Lifecycle ────────────────────────────────────────────
    SYSTEM_STARTED         = "system.started"
    SYSTEM_SHUTDOWN        = "system.shutdown"
    SYSTEM_CORE_FAILURE    = "system.core_failure"
    SYSTEM_MEMORY_CRITICAL = "system.memory_critical"
    SYSTEM_CPU_CRITICAL    = "system.cpu_critical"

    # ── Authentication ──────────────────────────────────────────────
    AUTH_LOGIN_SUCCESS     = "auth.login_success"
    AUTH_LOGIN_FAILURE     = "auth.login_failure"
    AUTH_BRUTE_FORCE       = "auth.brute_force"

    # ── High Availability ───────────────────────────────────────────
    HA_FAILOVER            = "ha.failover"

    # ── SIEM / Incidents ────────────────────────────────────────────
    SIEM_INCIDENT_CREATED   = "siem.incident_created"
    SIEM_INCIDENT_ESCALATED = "siem.incident_escalated"
    SIEM_INCIDENT_CLOSED    = "siem.incident_closed"

    # ── PKI / Certificates (cross-cutting concern — needed by system/pki) ──
    PKI_CERT_EXPIRING      = "pki.cert_expiring"
    PKI_CERT_INVALID       = "pki.cert_invalid"

    # ────────────────────────────────────────────────────────────────
    # Module-owned topics — defined here for discoverability but owned
    # by their respective modules.  Each module should also call
    # Topics.register() in its initialize() to validate no conflicts.
    # ────────────────────────────────────────────────────────────────

    # ── Malware / AV ────────────────────────────────────────────────
    MALWARE_DETECTED       = "malware.detected"

    # ── Email Security ──────────────────────────────────────────────
    EMAIL_THREAT           = "email.threat"

    # ── VPN ─────────────────────────────────────────────────────────
    VPN_FAILURE            = "vpn.failure"
    VPN_RESTORED           = "vpn.restored"
    VPN_CONNECTED          = "vpn.connected"
    VPN_DISCONNECTED       = "vpn.disconnected"

    # ── IDS/IPS ─────────────────────────────────────────────────────
    IDS_PORT_SCAN          = "ids.port_scan"

    # ── WAF ─────────────────────────────────────────────────────────
    WAF_BLOCK              = "waf.block"
    WAF_ALERT              = "waf.alert"

    # ── DNS Security ────────────────────────────────────────────────
    DNS_SUSPICIOUS         = "dns.suspicious"
    DNS_THREAT             = "dns.threat"

    # ── Web Filter ──────────────────────────────────────────────────
    WEB_FILTER_BLOCK       = "web_filter.block"

    # ── DLP ─────────────────────────────────────────────────────────
    DLP_INCIDENT           = "dlp.incident"

    # ── Captive Portal ───────────────────────────────────────────────
    CAPTIVE_PORTAL_LOGIN   = "captive_portal.login"    # guest/BYOD authenticated
    CAPTIVE_PORTAL_LOGOUT  = "captive_portal.logout"   # session expired or explicit logout
