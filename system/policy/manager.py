"""
system/policy/manager.py
=========================
Generic Policy Decision Point (PDP) — Zero module coupling.

Architecture (Phase 4 decoupling)
----------------------------------
Previously this file imported ACLEngine, AppControlEngine, WebFilterEngine and
IPSEngine directly from modules/. This was an architectural violation: the
system/ layer must not know about specific security modules.

The new design uses a *registration pattern*:
  - Each module registers its own policy engine via register_engine()
  - PolicyManager evaluates all registered engines in priority order
  - No module-specific imports remain here

Registration is done in each module's initialize() via ServiceContainer, e.g.::

    # In modules/firewall/module.py:
    def get_provided_services(self):
        return {'policy_engine_acl': self._acl_engine}

    # In modules/web_filter/module.py:
    def get_provided_services(self):
        return {'policy_engine_web': self._web_filter_engine}

The PolicyIntegrator in system/core/router/policy_integration.py retrieves
a pre-built PolicyManager from the ServiceContainer (populated during startup).
"""

import logging
from typing import Optional, List, Dict, Tuple, Callable, Any
from dataclasses import dataclass, field
from .schema import PolicyContext, Action

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Engine adapter protocol
# ---------------------------------------------------------------------------

class PolicyEngineProtocol:
    """
    Interface that every registered policy engine must satisfy.

    Engines do NOT have to subclass this — duck typing is acceptable.
    The only required method is `evaluate(context: PolicyContext) -> Action`.

    Web-style engines that take (url, domain) kwargs are handled by the
    optional `evaluate_web(url, domain) -> (Action, str)` method.
    """

    def evaluate(self, context: PolicyContext) -> Action:  # noqa: D102
        raise NotImplementedError

    def evaluate_web(self, url: str, domain: str) -> Tuple[Action, str]:
        """Optional: used by engines that work on URLs (WebFilter style)."""
        return self.evaluate(PolicyContext(
            src_ip='', dst_ip='', src_port=0, dst_port=0, protocol='',
            url=url, domain=domain,
        )), ''


# ---------------------------------------------------------------------------
# PolicyManager
# ---------------------------------------------------------------------------

@dataclass
class _EngineEntry:
    name: str
    engine: Any
    priority: int = 50          # lower = evaluated earlier
    web_style: bool = False     # True → call evaluate_web(url, domain)
    block_count: int = field(default=0, init=False)


class PolicyManager:
    """
    Generic Policy Decision Point (PDP).

    Aggregates ALLOW/BLOCK decisions from all registered policy engines.
    No module-specific logic lives here — engines self-register.

    Evaluation order:
        1. Access-Control engines (L3/L4 fast path)
        2. Adaptive ML engine (if set)
        3. Deep-inspection engines (L7, sorted by historical block-rate)
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._engines: List[_EngineEntry] = []
        self.adaptive_engine = None       # set externally (ML layer)
        logger.info("[PolicyManager] Initialised — awaiting engine registrations")

    # ------------------------------------------------------------------
    # Registration API
    # ------------------------------------------------------------------

    def register_engine(
        self,
        name: str,
        engine: Any,
        priority: int = 50,
        web_style: bool = False,
    ) -> None:
        """
        Register a policy engine.

        Args:
            name:       Unique engine identifier (used in logs & metrics).
            engine:     Object with an ``evaluate(PolicyContext) -> Action`` method.
                        Web-style engines should have ``evaluate_web(url, domain)``.
            priority:   Evaluation order — lower runs first (default 50).
            web_style:  If True, the engine is called with (url, domain) and
                        skipped when neither is available in the context.
        """
        # Replace existing entry with the same name
        self._engines = [e for e in self._engines if e.name != name]
        self._engines.append(_EngineEntry(name=name, engine=engine,
                                          priority=priority, web_style=web_style))
        self._engines.sort(key=lambda e: e.priority)
        logger.info("[PolicyManager] Engine registered: '%s' (priority=%d)", name, priority)

    def unregister_engine(self, name: str) -> None:
        """Remove a previously registered engine."""
        before = len(self._engines)
        self._engines = [e for e in self._engines if e.name != name]
        if len(self._engines) < before:
            logger.info("[PolicyManager] Engine unregistered: '%s'", name)

    def list_engines(self) -> List[str]:
        """Return names of all registered engines in evaluation order."""
        return [e.name for e in self._engines]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, context: PolicyContext) -> Action:
        """
        Evaluate *context* against all registered engines.

        Engines with lower priority numbers run first.
        The first BLOCK result short-circuits remaining checks (fast-path).
        """
        # 1. Fast-path engines (non-web-style, low priority numbers)
        for entry in self._engines:
            if entry.web_style:
                continue                # deferred to step 3
            action = self._call_engine(entry, context)
            if action == Action.BLOCK:
                self._feed_adaptive(context.src_ip, action, True, f"{entry.name}_block")
                entry.block_count += 1
                return Action.BLOCK

        # 2. Adaptive ML Policy (optional)
        if self.adaptive_engine:
            ml_action = self._run_adaptive(context)
            if ml_action == Action.BLOCK:
                return Action.BLOCK

        # 3. Web-style engines — sorted dynamically by block frequency
        web_entries = sorted(
            [e for e in self._engines if e.web_style],
            key=lambda e: e.block_count,
            reverse=True,
        )
        for entry in web_entries:
            if not (context.domain or context.url):
                continue
            action = self._call_web_engine(entry, context)
            if action == Action.BLOCK:
                self._feed_adaptive(context.src_ip, action, True, f"{entry.name}_block")
                entry.block_count += 1
                return Action.BLOCK

        self._feed_adaptive(context.src_ip, Action.ALLOW, False)
        return Action.ALLOW

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_engine(self, entry: _EngineEntry, context: PolicyContext) -> Action:
        try:
            return entry.engine.evaluate(context)
        except Exception as exc:
            logger.error("[PolicyManager] Engine '%s' raised an exception: %s",
                         entry.name, exc, exc_info=True)
            return Action.ALLOW       # fail-open to avoid blocking legitimate traffic

    def _call_web_engine(self, entry: _EngineEntry, context: PolicyContext) -> Action:
        try:
            result = entry.engine.evaluate_web(
                url=context.url or '', domain=context.domain or ''
            )
            # Support (action, reason) tuples or plain Action
            if isinstance(result, tuple):
                return result[0]
            return result
        except AttributeError:
            # Fallback to generic evaluate if evaluate_web not implemented
            return self._call_engine(entry, context)
        except Exception as exc:
            logger.error("[PolicyManager] Web engine '%s' raised an exception: %s",
                         entry.name, exc, exc_info=True)
            return Action.ALLOW

    def _run_adaptive(self, context: PolicyContext) -> Action:
        try:
            from system.ml_core.adaptive_policy import PolicyAction as MLPolicyAction
            ml_action, confidence, reason = self.adaptive_engine.evaluate(
                src_ip=context.src_ip,
                dst_ip=context.dst_ip,
                dst_port=context.dst_port,
                protocol=context.protocol,
                anomaly_score=0.0,
                reputation_score=100.0,
                pattern=context.app_id or 'unknown',
            )
            if ml_action == MLPolicyAction.BLOCK and confidence > 0.8:
                logger.warning("🧠 ML Adaptive Policy Blocked: %s → %s", context.src_ip, reason)
                self.adaptive_engine.add_feedback(
                    context.src_ip, ml_action, was_threat=True,
                    threat_type="ml_adaptive_block"
                )
                return Action.BLOCK
        except Exception as exc:
            logger.error("[PolicyManager] Adaptive engine error: %s", exc)
        return Action.ALLOW

    def _feed_adaptive(
        self, src_ip: str, action: Action, was_threat: bool, threat_type: str = None
    ) -> None:
        if not self.adaptive_engine:
            return
        try:
            from system.ml_core.adaptive_policy import PolicyAction as MLPolicyAction
            ml_action = MLPolicyAction.BLOCK if action == Action.BLOCK else MLPolicyAction.ALLOW
            self.adaptive_engine.add_feedback(src_ip, ml_action, was_threat, threat_type)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def load_policies(self) -> None:
        """Reload policies in all registered engines that support it."""
        for entry in self._engines:
            if hasattr(entry.engine, 'load_rules'):
                try:
                    entry.engine.load_rules()
                except Exception as exc:
                    logger.error("[PolicyManager] reload failed for '%s': %s", entry.name, exc)
        logger.info("[PolicyManager] Policies reloaded across %d engines", len(self._engines))

    def reload(self) -> None:
        """Alias for load_policies (backward compat)."""
        self.load_policies()
