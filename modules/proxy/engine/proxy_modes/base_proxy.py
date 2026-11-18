#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Base Proxy - Abstract Base Class for Proxy Modes
═══════════════════════════════════════════════════════════════════

Defines common interface and functionality for all proxy modes.

Author: Enterprise Security Team
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from modules.qos.qos_manager import QoSManager

logger = logging.getLogger(__name__)


@dataclass
class ProxyConnection:
    """Represents a proxied connection"""
    connection_id: str
    client_ip: str
    client_port: int
    target_host: str
    target_port: int
    protocol: str = "UNKNOWN"
    
    # Stream objects
    client_reader: Optional[asyncio.StreamReader] = None
    client_writer: Optional[asyncio.StreamWriter] = None
    server_reader: Optional[asyncio.StreamReader] = None
    server_writer: Optional[asyncio.StreamWriter] = None
    
    # Statistics
    start_time: datetime = None
    end_time: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()


class BaseProxy(ABC):
    """
    Abstract base class for proxy implementations
    
    All proxy modes must inherit from this class and implement
    the abstract methods.
    """
    
    def __init__(self, config: dict, inspection_pipeline=None, event_sink=None):
        self.config = config
        self.proxy_config = config.get('proxy', {})
        self.inspection_pipeline = inspection_pipeline
        self.event_sink = event_sink
        
        # QoS Integration — use Singleton to share state with Pipeline
        self.qos_manager = QoSManager.get_instance(config=config.get('qos', {}))
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
        }
        
        # Running state
        self.running = False
        self.servers = []
        self.active_sessions = {}
        
        logger.info("%s initialized", self.__class__.__name__)
    
    @abstractmethod
    async def start(self):
        """Start the proxy server"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the proxy server"""
        pass
    
    @abstractmethod
    async def handle_connection(self,
                               client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter):
        """
        Handle incoming client connection
        
        This is the main entry point for each connection.
        Must be implemented by subclasses.
        """
        pass
    
    async def relay_data(self,
                        reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        connection: ProxyConnection,
                        direction: str):
        """
        Relay data between two streams (WITH DEEP PACKET INSPECTION)
        
        Args:
            reader: Source stream
            writer: Destination stream
            connection: ProxyConnection object
            direction: 'client->server' or 'server->client'
        """
        try:
            buffer_size = self.proxy_config.get('buffer_size', 65536)
            
            idle_timeout = float(self.proxy_config.get('idle_timeout_seconds', 30.0))

            while True:
                try:
                    data = await asyncio.wait_for(reader.read(buffer_size), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    logger.debug(
                        "[BaseProxy] Idle connection timeout (%.1fs) for %s (%s) — terminating stream",
                        idle_timeout, connection.client_ip, direction
                    )
                    break

                if not data:
                    break
                    
                # Throttle data delivery based on QoS policies
                if self.qos_manager:
                    await self.qos_manager.throttle(connection.client_ip, len(data))
                    
                # ── Inspect content via InspectionBridge (Phase 10) ──────────────
                # Uses ContextBuilder → typed InspectionContext → InspectionBridge.check().
                # Falls back to legacy pipeline.inspect_async() if no bridge available.
                _bridge = getattr(self, '_inspection_bridge', None)
                if _bridge is not None:
                    try:
                        from modules.proxy.engine.context_builder import ContextBuilder
                        _builder = getattr(self, '_ctx_builder', None) or ContextBuilder(self.config)
                        _ctx = _builder.build_network_context(
                            client_addr=(connection.client_ip, connection.client_port),
                            target_host=connection.target_host,
                            target_port=connection.target_port,
                            protocol=connection.protocol,
                        )
                        _ctx.direction = 'outbound' if direction == 'client->server' else 'inbound'
                        _ctx.flow_id   = connection.connection_id

                        # Attach raw bytes as http body for app-layer plugins
                        if _ctx.http is not None:
                            _ctx.http.body = data
                        else:
                            from system.core.inspection_context import HttpInfo
                            _ctx.http = HttpInfo.empty()
                            _ctx.http.body = data

                        result = await _bridge.check(_ctx)

                        if result.is_blocked:
                            reasons = [f"[{f.plugin_name}] {f.description}" for f in result.findings]
                            logger.warning(
                                "Blocked by InspectionBridge: %s -> %s:%s (action=%s)",
                                connection.client_ip, connection.target_host,
                                connection.target_port, result.action.name
                            )
                            raise ConnectionAbortedError("Blocked by InspectionBridge")
                    except ConnectionAbortedError:
                        raise
                    except Exception as e:
                        logger.error("InspectionBridge error in %s: %s", self.__class__.__name__, e)

                elif getattr(self, 'inspection_pipeline', None):
                    # ── Legacy fallback path (forward_proxy / reverse_proxy) ──────
                    # NOTE: This path is deprecated. Subclasses should inject
                    # _inspection_bridge via __init__ instead of inspection_pipeline.
                    try:
                        from system.core.inspection_context import InspectionContext
                        context = InspectionContext(
                            src_ip=connection.client_ip,
                            dst_ip=connection.target_host,
                            src_port=connection.client_port,
                            dst_port=connection.target_port,
                            protocol=connection.protocol,
                            direction='outbound' if direction == 'client->server' else 'inbound',
                            flow_id=connection.connection_id,
                            timestamp=datetime.now().timestamp(),
                            metadata={'proxied': True, '_legacy_base_proxy': True},
                        )

                        result = await self.inspection_pipeline.inspect_async(context, data)

                        if result.is_blocked:
                            logger.warning(
                                "[LEGACY] Blocked by inspection: %s (action=%s)",
                                direction, result.action.name
                            )
                            reasons = [f"[{f.plugin_name}] {f.description}" for f in result.findings]

                            if getattr(self, 'event_sink', None):
                                try:
                                    from system.telemetry.events.event_schema import (
                                        create_event_from_proxy, EventVerdict,
                                    )
                                    evt = create_event_from_proxy(
                                        src_ip=connection.client_ip,
                                        dst_ip=connection.target_host,
                                        src_port=connection.client_port,
                                        dst_port=connection.target_port,
                                        protocol=connection.protocol,
                                        bytes_count=connection.bytes_sent + connection.bytes_received,
                                        packets_count=(connection.bytes_sent + connection.bytes_received) // 1400,
                                        verdict=EventVerdict.DROP,
                                        reason=" | ".join(reasons),
                                    )
                                    asyncio.create_task(self.event_sink.submit_event(evt))
                                except Exception as e:
                                    logger.debug("Block event sink push failed: %s", e)

                            raise ConnectionAbortedError("Blocked by inspection")
                    except ConnectionAbortedError:
                        raise
                    except Exception as e:
                        logger.error("Legacy inspection error in %s: %s", self.__class__.__name__, e)


                # Update statistics
                if direction == 'client->server':
                    connection.bytes_sent += len(data)
                    self.stats['bytes_sent'] += len(data)
                else:
                    connection.bytes_received += len(data)
                    self.stats['bytes_received'] += len(data)
                
                # Write data
                writer.write(data)
                await writer.drain()
                
        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            logger.debug(f"Connection reset ({direction})")
        except Exception as e:
            logger.debug(f"Relay error ({direction}): {e}")
        finally:
            if not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
    
    async def connect_to_upstream(self,
                                  target_host: str,
                                  target_port: int,
                                  ssl_context=None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to upstream server
        
        Args:
            target_host: Target hostname
            target_port: Target port
            ssl_context: Optional SSL context for TLS
        
        Returns:
            (reader, writer) tuple
        """
        try:
            if ssl_context:
                reader, writer = await asyncio.open_connection(
                    target_host, target_port,
                    ssl=ssl_context,
                    server_hostname=target_host
                )
            else:
                reader, writer = await asyncio.open_connection(
                    target_host, target_port
                )
            
            logger.debug(f"Connected to upstream: {target_host}:{target_port}")
            return reader, writer
            
        except Exception as e:
            logger.error(f"Failed to connect to {target_host}:{target_port}: {e}")
            raise
    
    def get_statistics(self) -> dict:
        """Get proxy statistics"""
        return {
            'total_connections': self.stats['total_connections'],
            'active_connections': self.stats['active_connections'],
            'bytes_sent': self.stats['bytes_sent'],
            'bytes_received': self.stats['bytes_received'],
        }
    
    def get_active_sessions(self) -> list:
        """Get active sessions from the proxy registry"""
        sessions = []
        for conn in list(self.active_sessions.values()):
            try:
                sessions.append({
                    "connection_id": conn.connection_id,
                    "client_ip": conn.client_ip,
                    "client_port": conn.client_port,
                    "target_host": conn.target_host,
                    "target_port": conn.target_port,
                    "protocol": conn.protocol,
                    "bytes_sent": conn.bytes_sent,
                    "bytes_received": conn.bytes_received,
                    "duration": (datetime.now() - conn.start_time).total_seconds() if conn.start_time else 0
                })
            except Exception:
                pass
        return sessions
    
    def _generate_connection_id(self, client_addr: tuple, target_host: str, target_port: int) -> str:
        """Generate unique connection ID"""
        return f"{client_addr[0]}:{client_addr[1]}->{target_host}:{target_port}"

    def _log_allowed_connection(self, connection, protocol: str, reason: str = "Connection completed"):
        """Emit an ALLOW telemetry event for a successfully closed connection."""
        if getattr(self, 'event_sink', None):
            try:
                from system.telemetry.events.event_schema import create_event_from_proxy, EventVerdict
                # Handle both ProxyConnection and ConnectionStats objects
                client_ip = getattr(connection, 'client_ip', None)
                target_host = getattr(connection, 'target_host', None)
                client_port = getattr(connection, 'client_port', None)
                target_port = getattr(connection, 'target_port', None)
                bytes_sent = getattr(connection, 'bytes_sent', 0)
                bytes_received = getattr(connection, 'bytes_received', 0)

                total_bytes = bytes_sent + bytes_received
                evt = create_event_from_proxy(
                    src_ip=client_ip,
                    dst_ip=target_host,
                    src_port=client_port,
                    dst_port=target_port,
                    protocol=protocol,
                    bytes_count=total_bytes,
                    packets_count=max(1, total_bytes // 1400),
                    verdict=EventVerdict.ALLOW,
                    reason=reason
                )
                asyncio.create_task(self.event_sink.submit_event(evt))
            except Exception as e:
                logger.debug(f"Event sink push failed: {e}")
