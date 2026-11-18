#!/usr/bin/env python3
import logging
import threading
from collections import OrderedDict
from typing import Optional

logger = logging.getLogger(__name__)

class HTTPCloaker:
    """
    Efficiently parses and modifies HTTP headers to hide server identity.
    Enterprise-grade rewrite: OOM protected (LRU), Keep-Alive supported, Fragment safe.
    """
    
    def __init__(self, config: dict):
        self.config = config.get('proxy', {}).get('hardening', {})
        self.cloaking_enabled = self.config.get('cloaking_enabled', False)
        self.server_banner = self.config.get('server_banner', "bunyanx-NGFW")
        
        # Convert strip headers to lower-case bytes for fast, safe matching
        self.strip_headers = [h.lower().encode('latin-1') for h in self.config.get('strip_headers', [])]
        self.server_banner_bytes = self.server_banner.encode('latin-1') if self.server_banner else b""
        
        # LRU Cache to track fragmented headers without OOM
        self.max_flows = 100000
        self._flow_buffers = OrderedDict()
        self._lock = threading.RLock()

    def _get_buffer(self, flow_id: str) -> Optional[bytes]:
        with self._lock:
            if flow_id in self._flow_buffers:
                self._flow_buffers.move_to_end(flow_id)
                return self._flow_buffers[flow_id]
            return None

    def _set_buffer(self, flow_id: str, buf: bytes):
        with self._lock:
            self._flow_buffers[flow_id] = buf
            self._flow_buffers.move_to_end(flow_id)
            if len(self._flow_buffers) > self.max_flows:
                self._flow_buffers.popitem(last=False)

    def _clear_buffer(self, flow_id: str):
        with self._lock:
            if flow_id in self._flow_buffers:
                del self._flow_buffers[flow_id]

    def process_data(self, data: bytes, direction: str, flow_id: str) -> bytes:
        """
        Processes a chunk of data. Buffers fragmented headers safely.
        Supports Keep-Alive by looking for HTTP/1. boundaries.
        """
        if not self.cloaking_enabled or direction != 'server->client' or not data:
            return data

        # If chunk starts with HTTP/1., it's a new response (supports Keep-Alive)
        if data.startswith(b'HTTP/1.'):
            self._set_buffer(flow_id, b"")

        buf = self._get_buffer(flow_id)
        
        # If we are not currently buffering headers for this flow, pass through.
        if buf is None:
            return data
            
        # We are buffering headers
        buf += data
        
        # Anti-Slowloris / Buffer-bloat protection: max 8KB for HTTP headers
        if len(buf) > 8192:
            self._clear_buffer(flow_id)
            return buf  # Pass whatever we have uncloaked to avoid dropping traffic on extreme headers

        header_end = buf.find(b'\r\n\r\n')
        if header_end != -1:
            # Headers are completely buffered!
            headers = buf[:header_end]
            body = buf[header_end + 4:] # +4 to skip \r\n\r\n
            
            # Cloak headers
            new_headers = self._cloak_headers(headers)
            
            # We are done with this response's headers, stop buffering until next HTTP/1.
            self._clear_buffer(flow_id)
            
            return new_headers + b'\r\n\r\n' + body
            
        else:
            # Headers are incomplete (fragmented). Save buffer and hold the packet.
            self._set_buffer(flow_id, buf)
            return b""  # Return empty bytes to hold the stream until headers complete

    def _cloak_headers(self, header_part: bytes) -> bytes:
        try:
            lines = header_part.split(b'\r\n')
            new_lines = []
            server_header_found = False
            
            for line in lines:
                if b':' not in line:
                    new_lines.append(line)
                    continue
                
                header_name, header_value = line.split(b':', 1)
                header_name_lower = header_name.strip().lower()
                
                # Check if we should strip this header
                if header_name_lower in self.strip_headers:
                    # Special case: replace Server instead of stripping it
                    if header_name_lower == b'server' and self.server_banner_bytes:
                        new_lines.append(b"Server: " + self.server_banner_bytes)
                        server_header_found = True
                    continue
                
                new_lines.append(line)
            
            # If Server header was missing but required, add it
            if not server_header_found and b'server' in self.strip_headers and self.server_banner_bytes:
                 new_lines.append(b"Server: " + self.server_banner_bytes)

            return b'\r\n'.join(new_lines)

        except Exception as e:
            logger.error(f"Error cloaking HTTP headers: {e}")
            return header_part

    def clear_flow(self, flow_id: str):
        """Clean up when a flow is explicitly closed by the router"""
        self._clear_buffer(flow_id)
