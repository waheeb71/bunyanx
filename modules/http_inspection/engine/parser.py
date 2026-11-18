from typing import Dict, Optional
import logging
import gzip
import zlib

class HTTPParser:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def parse(self, bounded_data: bytes) -> Optional[Dict]:
        #hi
        if not bounded_data or not bounded_data.strip():
            return None
        try:
            # Safely split headers and body
            parts = bounded_data.split(b'\r\n\r\n', 1)
            if len(parts) == 1:
                parts = bounded_data.split(b'\n\n', 1)
            
            if len(parts) == 1:
                header_data = parts[0]
                body_data = b""
            else:
                header_data = parts[0]
                body_data = parts[1]

            text = header_data.decode('utf-8', errors='replace')
            lines = text.splitlines()
            if not lines:
                raise ValueError("Empty HTTP Data")

            first_line = lines[0]
            http_data = {}

            if first_line.startswith('HTTP/'):
                first_parts = first_line.split(' ', 2)
                http_data['type'] = 'response'
                http_data['version'] = first_parts[0] if len(first_parts) > 0 else ''
                http_data['status_code'] = first_parts[1] if len(first_parts) > 1 else ''
                http_data['status_text'] = first_parts[2] if len(first_parts) > 2 else ''
            else:
                first_parts = first_line.split(' ')
                if len(first_parts) >= 3:
                    http_data['type'] = 'request'
                    http_data['method'] = first_parts[0]
                    http_data['url'] = first_parts[1]
                    http_data['version'] = first_parts[2]

            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key_lower = key.strip().lower()
                    val_strip = value.strip()
                    if key_lower in headers:
                        headers[key_lower] += f", {val_strip}"
                    else:
                        headers[key_lower] = val_strip

            http_data['headers'] = headers

            if body_data:
                te = headers.get('transfer-encoding', '').lower()
                if 'chunked' in te:
                    reassembled = b''
                    idx = 0
                    while idx < len(body_data):
                        crlf_idx = body_data.find(b'\r\n', idx)
                        if crlf_idx == -1:
                            break
                        chunk_size_hex = body_data[idx:crlf_idx].split(b';')[0].strip()
                        try:
                            chunk_size = int(chunk_size_hex, 16)
                        except ValueError:
                            raise ValueError(f"Malformed chunk size: {chunk_size_hex}")
                        if chunk_size == 0:
                            break
                        start = crlf_idx + 2
                        end = start + chunk_size
                        reassembled += body_data[start:end]
                        idx = end + 2
                    body_data = reassembled

                encoding = headers.get('content-encoding', '').lower()
                try:
                    if 'gzip' in encoding:
                        body_data = gzip.decompress(body_data)
                    elif 'deflate' in encoding:
                        try:
                            body_data = zlib.decompress(body_data)
                        except zlib.error:
                            body_data = zlib.decompress(body_data, -zlib.MAX_WBITS)
                except Exception as e:
                    self.logger.warning(f"Failed to decompress body: {e}")
                
                http_data['body'] = body_data.decode('utf-8', errors='replace')

            if 'content-type' in headers:
                http_data['content_type'] = headers['content-type']

            if 'content-length' in headers:
                try:
                    http_data['content_length'] = int(headers['content-length'])
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Invalid Content-Length header value: {e}")

            return http_data

        except Exception as e:
            self.logger.warning(f"HTTP parse failed on {len(bounded_data)} bytes: {type(e).__name__}: {e}")
            raise ValueError(f"Malformed HTTP Data: {e}")

