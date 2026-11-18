from typing import Dict, List
import hashlib
from urllib.parse import unquote
from system.core.framework import InspectionResult, InspectionAction, InspectionFinding

MAX_URL_LENGTH = 2048
DANGEROUS_METHODS = {'TRACE', 'TRACK', 'DEBUG', 'CONNECT'}

import regex as re

def safe_search(regex, text, timeout=0.1):
    import threading
    import queue
    res_queue = queue.Queue()
    def target():
        try:
            match = regex.search(text)
            res_queue.put((True, match))
        except Exception as e:
            res_queue.put((False, e))
            
    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    try:
        success, res = res_queue.get(timeout=timeout)
        if success:
            return res
        else:
            raise res
    except queue.Empty:
        raise TimeoutError("Regex matching timed out")

class HTTPScanner:
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name

    def inspect_method(self, http_data: Dict, result: InspectionResult, block_dangerous: bool) -> None:
        method = http_data.get('method', '').upper()

        if method in DANGEROUS_METHODS and block_dangerous:
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                severity='HIGH',
                category='http_method',
                description=f"Dangerous HTTP method: {method}",
                plugin_name=self.plugin_name,
                confidence=1.0,
                evidence={'method': method}
            ))

    def inspect_url(self, http_data: Dict, result: InspectionResult, patterns: List[dict], max_url_len: int = MAX_URL_LENGTH) -> None:
        url = http_data.get('url', '')

        if len(url) > max_url_len:
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                severity='HIGH',
                category='http_url',
                description=f"Abnormally long URL dropping to prevent overflow: {len(url)} bytes",
                plugin_name=self.plugin_name,
                confidence=0.9,
                evidence={'url_length': len(url)}
            ))
            return

        url_decoded = unquote(url)

        for p in patterns:
            try:
                if safe_search(p['regex'], url, timeout=0.1) or safe_search(p['regex'], url_decoded, timeout=0.1):
                    result.action = InspectionAction.BLOCK
                    result.findings.append(InspectionFinding(
                        severity=p['severity'],
                        category='http_url',
                        description=p['description'] or "Suspicious URL pattern detected",
                        plugin_name=self.plugin_name,
                        confidence=0.95,
                        evidence={'url': url[:500], 'pattern_id': p['id']}
                    ))
            except TimeoutError:
                result.action = InspectionAction.BLOCK
                result.findings.append(InspectionFinding('HIGH', 'http_url', 'ReDoS Timeout during URL scan', self.plugin_name, 1.0, {'pattern_id': p['id']}))

    def inspect_headers(self, http_data: Dict, result: InspectionResult, patterns: List[dict]) -> None:
        headers = http_data.get('headers', {})
        for p in patterns:
            target_key = p['target_key']
            if not target_key:
                continue

            target_key_lower = target_key.lower()
            if target_key_lower in headers:
                val = headers[target_key_lower]
                try:
                    if safe_search(p['regex'], val, timeout=0.1):
                        result.action = InspectionAction.BLOCK
                        val_hash = hashlib.sha256(val.encode()).hexdigest()[:16]
                        result.findings.append(InspectionFinding(
                            severity=p['severity'],
                            category='http_header',
                            description=p['description'] or f"Suspicious {target_key} header",
                            plugin_name=self.plugin_name,
                            confidence=0.8,
                            evidence={
                                'header': target_key,
                                'value_hash': val_hash,
                                'value_length': len(val),
                                'pattern_id': p['id']
                            }
                        ))
                except TimeoutError:
                    result.action = InspectionAction.BLOCK
                    result.findings.append(InspectionFinding('HIGH', 'http_header', 'ReDoS Timeout during header scan', self.plugin_name, 1.0, {'pattern_id': p['id']}))

    def inspect_body(self, http_data: Dict, result: InspectionResult, patterns: List[dict]) -> None:
        body = http_data.get('body', '')
        if not body:
            return

        for p in patterns:
            try:
                if safe_search(p['regex'], body, timeout=0.1):
                    result.action = InspectionAction.BLOCK
                    body_sample = body[:500]
                    body_hash = hashlib.sha256(body_sample.encode()).hexdigest()[:16]
                    result.findings.append(InspectionFinding(
                        severity=p['severity'],
                        category='http_body',
                        description=p['description'] or "Suspicious body content",
                        plugin_name=self.plugin_name,
                        confidence=0.9,
                        evidence={
                            'body_hash': body_hash,
                            'body_length': len(body),
                            'pattern_id': p['id']
                        }
                    ))
            except TimeoutError:
                result.action = InspectionAction.BLOCK
                result.findings.append(InspectionFinding('HIGH', 'http_body', 'ReDoS Timeout during body scan', self.plugin_name, 1.0, {'pattern_id': p['id']}))

    def inspect_uploads(self, http_data: Dict, result: InspectionResult, max_upload_size_mb: int) -> None:
        content_type = http_data.get('content_type', '')
        content_length = http_data.get('content_length', 0)

        if 'multipart/form-data' in content_type:
            size_mb = content_length / (1024 * 1024)
            if size_mb > max_upload_size_mb:
                result.action = InspectionAction.BLOCK
                result.findings.append(InspectionFinding(
                    severity='HIGH',
                    category='http_upload',
                    description=f"Upload exceeds NG limits ({size_mb:.2f} > {max_upload_size_mb} MB)",
                    plugin_name=self.plugin_name,
                    confidence=1.0,
                    evidence={'size_mb': size_mb, 'limit_mb': max_upload_size_mb}
                ))
