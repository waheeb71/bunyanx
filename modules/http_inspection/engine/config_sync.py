import regex as re
import time
import logging
import threading
from typing import Dict, List
from sqlalchemy.orm import Session
from modules.http_inspection.models import HTTPSuspiciousPattern, HTTPInspectionConfig

MAX_PATTERN_LENGTH = 200

class ConfigManager:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.last_db_sync = 0
        self.config_cache = None
        self.patterns_cache: Dict[str, List[dict]] = {"url": [], "header": [], "body": []}
        self.cache_ttl = 5
        self.sync_lock = threading.Lock()

    def sync_config(self, get_db_session) -> None:
        now = time.time()
        if now - self.last_db_sync < self.cache_ttl:
            return

        if not self.sync_lock.acquire(blocking=False):
            return  # Let another thread handle the sync; continue with current cache
            
        try:
            # Check again inside the lock
            if time.time() - self.last_db_sync < self.cache_ttl:
                return
                
            db: Session = get_db_session()
            try:
                config = db.query(HTTPInspectionConfig).first()
                new_cache_ttl = self.cache_ttl
                new_config_cache = None
                
                max_pat_len = MAX_PATTERN_LENGTH
                if config:
                    new_config_cache = {
                        "is_active": config.is_active,
                        "mode": config.mode,
                        "block_dangerous_methods": config.block_dangerous_methods,
                        "scan_headers": config.scan_headers,
                        "scan_body": config.scan_body,
                        "max_upload_size_mb": config.max_upload_size_mb,
                        "cache_ttl_seconds": config.cache_ttl_seconds,
                        "url_max_length": getattr(config, "url_max_length", 2048),
                        "max_pattern_length": getattr(config, "max_pattern_length", 500),
                        "log_pool_max_workers": getattr(config, "log_pool_max_workers", 8),
                    }
                    new_cache_ttl = config.cache_ttl_seconds
                    max_pat_len = new_config_cache["max_pattern_length"]

                patterns = db.query(HTTPSuspiciousPattern).filter(HTTPSuspiciousPattern.enabled == True).all()

                categorized: Dict[str, List[dict]] = {"url": [], "header": [], "body": []}
                for p in patterns:
                    try:
                        flags = re.IGNORECASE | re.DOTALL if p.target == 'body' else re.IGNORECASE
                        compiled = self.safe_compile(p.pattern, flags, max_length=max_pat_len)
                        entry = {
                            "id": p.id,
                            "target": p.target,
                            "severity": p.severity,
                            "description": p.description,
                            "regex": compiled,
                            "target_key": p.target_key
                        }
                        bucket = categorized.get(p.target)
                        if bucket is not None:
                            bucket.append(entry)
                        else:
                            self.logger.warning(f"Unknown pattern target '{p.target}' in rule {p.id} — skipping")
                    except ValueError as ve:
                        self.logger.error(f"Rejected unsafe pattern rule {p.id}: {ve}")
                    except re.error as compile_err:
                        self.logger.error(f"Bad regex syntax in rule {p.id}: {compile_err}")

                # Atomic pointer swap
                self.config_cache = new_config_cache
                self.patterns_cache = categorized
                self.cache_ttl = new_cache_ttl
                self.last_db_sync = time.time()
            except Exception as e:
                self.logger.error(f"Failed to sync HTTP Inspection config: {e}")
            finally:
                db.close()
        finally:
            self.sync_lock.release()

    def safe_compile(self, pattern: str, flags: int, max_length: int = MAX_PATTERN_LENGTH) -> re.Pattern:
        if len(pattern) > max_length:
            raise ValueError(f"Pattern too long ({len(pattern)} chars > {max_length} limit)")

        # ReDoS prevention: detect nested repetition characters: +, *, ? or {n,m} inside a group followed by another quantifier
        import re as std_re
        clean_pattern = std_re.sub(r'\\.', '', pattern)
        if std_re.search(r'\([^)]*([*+?]|{\d*,?\d*})[^)]*\)([*+?]|{\d*,?\d*})', clean_pattern):
            raise ValueError("Potential ReDoS pattern: catastrophic nested quantifiers are not allowed")

        return re.compile(pattern, flags)
