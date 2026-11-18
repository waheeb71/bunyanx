"""
system/database/model_registry.py
====================================
Alembic / SQLAlchemy model auto-discovery.

Problem
-------
Alembic's ``autogenerate`` only sees models whose classes have been imported
into the Python process before the migration runs.  Previously, all module
models lived in ``system/database/database.py``.  As modules move their own
models into ``modules/<name>/models.py``, those models become invisible to
Alembic unless we explicitly import them.

Solution
--------
This file acts as a **model import hub**:
  - Import every module's ``models.py`` so that their ``Base``-derived classes
    are registered in ``Base.metadata`` before Alembic inspects it.
  - Called from ``system/database/migrations/env.py`` after
    ``from system.database.database import Base``.

Usage (in env.py)::

    from system.database.database import Base
    import system.database.model_registry  # noqa — registers all module models
    target_metadata = Base.metadata

Adding a new module's models
-----------------------------
Simply import the module's ``models.py`` file here.  If the import fails
(e.g., optional dependency not installed), wrap it in a try/except so that
Alembic doesn't break for other modules.
"""

import logging

logger = logging.getLogger(__name__)


def _safe_import(module_path: str) -> None:
    """Import a module for its side-effects (model registration).  Log but
    do not raise if the import fails — keeps Alembic operational."""
    try:
        __import__(module_path)
    except ImportError as exc:
        logger.debug("Model registry: optional import skipped — %s (%s)", module_path, exc)
    except Exception as exc:
        logger.warning("Model registry: failed to import %s: %s", module_path, exc)


# ── Module models ────────────────────────────────────────────────────────────
# Add one line per module that owns database models.
# Order does not matter for metadata registration.

_safe_import("modules.waf.models")               # WAFTrainingData (migrated Phase 2)
_safe_import("modules.firewall.models")           # FirewallConfig, if any
_safe_import("modules.dns_security.models")       # DNSFilterRule, DNSModuleConfig
_safe_import("modules.ids_ips.models")            # IPSConfig, IPSSignature
_safe_import("modules.web_filter.models")         # WebFilterConfig, WebFilterCategory
_safe_import("modules.dlp.models")                # DLPConfig, DLPRule
_safe_import("modules.email_security.models")     # EmailLog
_safe_import("modules.vpn.models")                # VPNConfig, VPNPeer (future move)
_safe_import("modules.uba.models")                # UBAUserProfile, UBAEvent, UBAConfig
_safe_import("modules.predictive_ai.models")      # PredictiveAI-specific models
_safe_import("modules.ssl_inspection.models")     # SSL cert / CA models
_safe_import("modules.qos.models")                # QoSConfig (future move)
_safe_import("modules.malware_av.models")         # AV scan results
_safe_import("modules.proxy.models")              # Proxy session logs

logger.debug("Model registry: all module models imported into Base.metadata")
