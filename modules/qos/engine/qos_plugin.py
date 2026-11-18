"""
Enterprise bunyanx — QoS Inspector Plugin

Lightweight InspectorPlugin that integrates the QoSManager into the
inspection pipeline. Runs at LOWEST priority (after all security checks)
to apply bandwidth shaping without blocking security decisions.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionResult,
    InspectionFinding, InspectionAction, PluginPriority,
)

logger = logging.getLogger(__name__)


class QoSPlugin(InspectorPlugin):
    """
    Quality of Service bandwidth-enforcement plugin.

    In 'monitor' mode: logs throttle decisions but always allows traffic.
    In 'enforce' mode: drops packets that exceed the configured rate limit.
    """

    PLUGIN_NAME = "qos"

    def __init__(
        self,
        db_manager=None,
        config=None,         # QoSConfig DB row
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__(
            name=self.PLUGIN_NAME,
            priority=PluginPriority.LOWEST,
            logger=logger or logging.getLogger(__name__),
        )
        # Default to monitor mode
        self._qos_manager = None

        try:
            from modules.qos.qos_manager import QoSManager
            # Convert DB model or Dict to manager config
            cfg_dict = {}
            if config:
                cfg_dict = {
                    "enabled":                config.enabled,
                    "mode":                   getattr(config, 'mode', 'monitor'),
                    "default_user_rate_bytes": config.default_user_rate_bytes,
                    "default_user_burst_bytes":config.default_user_burst_bytes,
                }
            
            self._qos_manager = QoSManager.get_instance(config=cfg_dict, db_manager=db_manager)
            mode = getattr(self._qos_manager, 'mode', 'monitor') or 'monitor'
            self.logger.info("QoSPlugin initialized (mode=%s, enabled=%s)", mode, self._qos_manager.enabled)
        except Exception as exc:
            self.logger.error("QoSPlugin: Initialization failed: %s", exc)

    def can_inspect(self, context: InspectionContext) -> bool:
        # Optimized check: skip if manager is missing or disabled
        if not self._qos_manager or not self._qos_manager.enabled:
            return False
        # Skip already proxied/throttled traffic to avoid double consumption.
        # Phase 10: check context.tags first (set by ContextBuilder), then metadata fallback.
        if "proxied" in (context.tags or set()):
            return False
        if context.metadata and context.metadata.get("proxied"):
            return False
        return context.protocol in ("TCP", "UDP")

    def inspect(
        self,
        context: InspectionContext,
        data: bytes = b"",
    ) -> InspectionResult:
        start = time.time()
        result = InspectionResult(action=InspectionAction.ALLOW)

        if not self._qos_manager or not self._qos_manager.enabled:
            return result

        # Phase 10: body may live in context.http.body when called via InspectionBridge
        if not data and context.http:
            if hasattr(context.http, 'body') and context.http.body:
                data = context.http.body
            elif isinstance(context.http, dict) and context.http.get('body'):
                data = context.http.get('body')

        payload_size = len(data) if data is not None else 0
        
        # Inbound = download (limit by dst_ip), Outbound/default = upload (limit by src_ip)
        direction = getattr(context, 'direction', 'outbound')
        if direction == 'inbound':
            target_ip = context.dst_ip
        else:
            target_ip = context.src_ip
        target_ip = target_ip or "0.0.0.0"

        # Use the unified high-performance sync check
        allowed = self._qos_manager.check_traffic(target_ip, payload_size)

        if not allowed:
            mode = getattr(self._qos_manager, 'mode', 'monitor') or 'monitor'
            log_msg = f"QoS Rate limit exceeded for {target_ip} ({payload_size} bytes, direction: {direction}, mode: {mode})"
            if mode == "enforce":
                self.logger.warning(f"🚫 {log_msg}")
            else:
                self.logger.info(f"⚠️ {log_msg}")

            finding = InspectionFinding(
                plugin_name=self.name,
                severity="INFO",
                category="QoS",
                description=f"Rate limited: {target_ip} exceeded bandwidth ({payload_size} bytes)",
                confidence=1.0,
                recommends_block=(mode == "enforce"),
                metadata={
                    "target_ip": target_ip, 
                    "payload_bytes": payload_size,
                    "mode": mode,
                    "direction": direction
                },
            )
            result.findings.append(finding)

            if mode == "enforce":
                result.action = InspectionAction.BLOCK
                try:
                    from system.events.bus import EventBus
                    from system.events.topics import Topics
                    EventBus.publish_from_thread(Topics.RESPONSE_BLOCK, {
                        "src_ip": target_ip,
                        "reason": f"QoS Rate limit exceeded ({payload_size} bytes)",
                        "module": "qos",
                    })
                except Exception as exc:
                    self.logger.debug("Failed to publish QoS block to EventBus: %s", exc)

        result.processing_time_ms = (time.time() - start) * 1000
        return result
