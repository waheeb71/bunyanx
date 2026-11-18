"""
Enterprise bunyanx v2.0 - HTTP Inspector Plugin

Deep inspection of HTTP/HTTPS clear-text traffic (via Transparent Proxy).
This module acts as the orchestrator for the HTTP inspection process,
delegating tasks to specialized modules.
"""

import logging
from typing import Dict, Optional
from system.database.database import SessionLocal

from system.core.framework import (
    InspectorPlugin,
    PluginPriority,
    InspectionContext,
    InspectionResult,
    InspectionAction
)

from .parser import HTTPParser
from .scanner import HTTPScanner
from .config_sync import ConfigManager
from .event_logger import EventLogger

MAX_INSPECTION_BUFFER_SIZE = 32 * 1024 * 1024  # 32 MB max read for full file upload inspection


class HTTPInspector(InspectorPlugin):
    """
    HTTP/HTTPS traffic inspector with WAF-grade detection.
    Acts as the orchestrator for the HTTP inspection engine.
    """

    def __init__(
        self,
        priority: PluginPriority = PluginPriority.HIGH,
        logger: Optional[logging.Logger] = None
    ):
        super().__init__(
            name="HTTP Inspector",
            priority=priority,
            logger=logger
        )

        # Initialize sub-components
        self.parser = HTTPParser(self.logger)
        self.scanner = HTTPScanner(self.name)
        self.config_manager = ConfigManager(self.logger)
        self.event_logger = EventLogger(self.logger)

    # Note: Properties to maintain backward compatibility with tests
    @property
    def _patterns_cache(self):
        return self.config_manager.patterns_cache

    @_patterns_cache.setter
    def _patterns_cache(self, value):
        self.config_manager.patterns_cache = value

    @property
    def _config_cache(self):
        return self.config_manager.config_cache

    @_config_cache.setter
    def _config_cache(self, value):
        self.config_manager.config_cache = value

    @property
    def _last_db_sync(self):
        return self.config_manager.last_db_sync

    @_last_db_sync.setter
    def _last_db_sync(self, value):
        self.config_manager.last_db_sync = value

    @property
    def _safe_compile(self):
        return self.config_manager.safe_compile

    @property
    def _emit_ai_event(self):
        return self.event_logger.emit_ai_event

    @_emit_ai_event.setter
    def _emit_ai_event(self, value):
        self.event_logger.emit_ai_event = value

    @property
    def _log_executor(self):
        return self.event_logger.log_executor

    @property
    def _ai_logger(self):
        return self.event_logger.ai_logger

    def can_inspect(self, context: InspectionContext) -> bool:
        """Check if this is HTTP/HTTPS or Decrypted Proxy traffic.

        The transparent proxy sets context.protocol to one of:
          - 'TCP'      → plain HTTP connection
          - 'TCP/TLS'  → HTTPS connection (MITM-decrypted)
          - 'HTTP'     → explicitly parsed HTTP from proxy layer
        All three should be inspected on known HTTP ports.
        """
        # FIX: Added email ports (25, 587, 465, 143, 993) so HTTP Inspector
        # doesn't skip VIP email connections silently. Also added common
        # dev/API ports 8080, 8443, 3000, 5000.
        http_ports = {
            # HTTP / HTTPS
            80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
            # Email (VIP pass-through)
            25,    # SMTP
            587,   # SMTP Submission
            465,   # SMTPS
            143,   # IMAP
            993,   # IMAPS
        }
        proto = context.protocol.upper()

        # FIX-HTTP: Accept TCP, TCP/TLS, HTTP, and HTTPS — previously skipped HTTPS-labelled traffic.
        proto_ok = proto.startswith('TCP') or proto in ('HTTP', 'HTTPS')

        result = proto_ok and (
            context.dst_port in http_ports or context.src_port in http_ports
        )
        if result:
            self.logger.debug(
                "[HTTPInspector] can_inspect=True | proto=%s dst_port=%s src_port=%s",
                context.protocol, context.dst_port, context.src_port
            )
        return result


    def get_db_session(self):
        return SessionLocal()

    def inspect(
        self,
        context: InspectionContext,
        data: bytes = b""
    ) -> InspectionResult:
        result = InspectionResult(action=InspectionAction.ALLOW)

        if not data:
            # VIP connections pass b"" — log at debug so we know we were called
            self.logger.debug(
                "[HTTPInspector] inspect called with empty data (VIP pass-through) "
                "for %s:%s", context.src_ip, context.dst_port
            )
            return result

        try:
            # 1. Payload Size Check
            if len(data) > MAX_INSPECTION_BUFFER_SIZE:
                result.action = InspectionAction.BLOCK
                from system.core.framework import InspectionFinding
                finding = InspectionFinding(
                    severity='HIGH',
                    category='http_size_overflow',
                    description=f"Payload exceeds maximum inspection limit ({len(data)} > {MAX_INSPECTION_BUFFER_SIZE} bytes). Blocking to prevent bypass.",
                    plugin_name=self.name,
                    confidence=1.0,
                    evidence={'payload_size': len(data)}
                )
                result.findings.append(finding)
                
                self.config_manager.sync_config(self.get_db_session)
                config = self.config_manager.config_cache or {}
                mode = config.get('mode', 'enforce')
                
                self.event_logger.log_attack_async(self.get_db_session, {}, finding, context, mode)
                result = self._apply_mode_policy(result, mode)
                self.event_logger.emit_ai_event({}, result, context)
                return result

            # 2. Parse HTTP
            http_data = self.parser.parse(data)
            if not http_data:
                return result

            result.metadata['http'] = http_data

            # 3. Sync Config
            self.config_manager.sync_config(self.get_db_session)
            config = self.config_manager.config_cache
            if not config or not config.get('is_active', False):
                return result

            # 4. Scan
            if 'method' in http_data:
                self.scanner.inspect_method(http_data, result, config.get('block_dangerous_methods', False))

            if 'url' in http_data:
                url_limit = config.get('url_max_length', 2048) if config else 2048
                self.scanner.inspect_url(http_data, result, self.config_manager.patterns_cache.get("url", []), max_url_len=url_limit)

            if 'headers' in http_data and config.get('scan_headers', False):
                # SSL-Aware: الـ Proxy يُضيف/يُعدل headers عند فك تشفير HTTPS
                # (مثل Via, X-Forwarded-For) → تُطابق أنماط proxied attacks.
                # نتخطى فحص الـ headers للحركة المفكوكة فقط.
                # URL, Body, Method: يُفحصون بالكامل — لا تأثير على الحماية.
                if context.is_ssl_inspected:
                    self.logger.debug(
                        "[HTTPInspector][SSL-Aware] Skipping header scan "
                        "(Proxy-modified headers unreliable) for %s",
                        context.src_ip,
                    )
                else:
                    self.scanner.inspect_headers(
                        http_data, result, self.config_manager.patterns_cache.get("header", [])
                    )


            if 'body' in http_data and config.get('scan_body', False):
                self.scanner.inspect_body(http_data, result, self.config_manager.patterns_cache.get("body", []))

            if 'content_type' in http_data:
                self.scanner.inspect_uploads(http_data, result, config.get('max_upload_size_mb', 10))

            return self._finalize(result, http_data, context)

        except Exception as e:
            self.logger.error(f"HTTP inspection failed: {e}")
            result.action = InspectionAction.BLOCK
            from system.core.framework import InspectionFinding
            finding = InspectionFinding(
                severity='HIGH',
                category='inspection_failure',
                description=f"Fail-Closed: Dropping malformed or erroneous traffic. {e}",
                plugin_name=self.name,
                confidence=1.0,
                evidence={'error': str(e)}
            )
            result.findings.append(finding)
            
            self.config_manager.sync_config(self.get_db_session)
            config = self.config_manager.config_cache or {}
            mode = config.get('mode', 'enforce')
            
            self.event_logger.log_attack_async(self.get_db_session, {}, finding, context, mode)
            result = self._apply_mode_policy(result, mode)
            self.event_logger.emit_ai_event({}, result, context)
            return result

        return result

    def _finalize(self, result: InspectionResult, http_data: Dict, context: InspectionContext) -> InspectionResult:
        if result.action == InspectionAction.BLOCK and result.findings:
            config = self.config_manager.config_cache or {}
            mode = config.get('mode', 'enforce')

            for finding in result.findings:
                self.event_logger.log_attack_async(self.get_db_session, http_data, finding, context, mode)
                
            result = self._apply_mode_policy(result, mode)

        self.event_logger.emit_ai_event(http_data, result, context)
        return result

    def _apply_mode_policy(self, result: InspectionResult, mode: str) -> InspectionResult:
        if mode == 'monitor':
            result.action = InspectionAction.LOG_ONLY
        return result

    def stop(self) -> None:
        """Cleanly shutdown background event logging worker pool."""
        if hasattr(self, 'event_logger'):
            self.event_logger.stop()

