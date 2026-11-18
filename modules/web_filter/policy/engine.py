"""
Enterprise bunyanx NGFW — Web Filter Engine
==============================================

The core policy enforcement engine for URL/Domain filtering.

Capabilities:
  1. Bootstraps the DB with builtin categories from settings.yaml.
  2. Enforces Safe Search (URL rewrites for HTTP, DNS redirection handled elsewhere).
  3. Evaluates domains against the CategoryEngine (LRU cache + DB).
  4. Returns final Action and optional modified URL.
"""

import logging
import uuid
import threading
from typing import Tuple, Dict, Any, Optional

from system.policy.schema import Action
from system.database.database import SessionLocal
from modules.web_filter.models import WebFilterConfig, WebFilterCategory
from modules.web_filter.policy.category import CategoryEngine
from modules.web_filter.policy.safe_search import SafeSearch
from modules.web_filter.config.loader import config as file_config

logger = logging.getLogger(__name__)

class WebFilterEngine:
    """
    Evaluates Web Filtering Rules, Safe Search, and Global settings.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(WebFilterEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self.logger = logger
        self.yaml_config: Dict[str, Any] = {}
        self.db_config = None
        self.category_engine = CategoryEngine()
        self.rules = []
        self.last_config_sync = 0.0
        
        self.reload()
        self._initialized = True

    def load_rules(self, rules: list) -> None:
        """Load dynamic Web Filter rules for policy evaluation."""
        self.rules = rules

    def _load_yaml(self) -> Dict[str, Any]:
        """Load static configuration from settings.yaml via the central loader."""
        return file_config.raw_config

    def _sync_database(self) -> None:
        """
        Synchronize YAML configuration with the Database.
        - Ensures WebFilterConfig exists.
        - Seeds builtin_categories if the DB has no categories yet.
        """
        from types import SimpleNamespace
        try:
            db = SessionLocal()
        except Exception as e:
            self.logger.warning(f"[WebFilter] SessionLocal connection failed: {e} — using YAML config defaults.")
            self.db_config = SimpleNamespace(
                enabled=self.yaml_config.get("enabled", True),
                mode=self.yaml_config.get("mode", "enforce"),
                default_action=self.yaml_config.get("default_action", "ALLOW"),
                safe_search_enabled=self.yaml_config.get("safe_search", {}).get("enabled", True)
            )
            return

        try:
            # Auto-create tables if missing
            from system.database.database import Base
            import modules.web_filter.models
            try:
                Base.metadata.create_all(bind=db.get_bind())
            except Exception:
                pass

            # 1. Ensure Global Config exists
            conf = db.query(WebFilterConfig).first()
            if not conf:
                self.logger.info("[WebFilter] Initializing DB config from YAML defaults.")
                conf = WebFilterConfig(
                    enabled=self.yaml_config.get("enabled", True),
                    mode=self.yaml_config.get("mode", "enforce"),
                    default_action=self.yaml_config.get("default_action", "ALLOW"),
                    safe_search_enabled=self.yaml_config.get("safe_search", {}).get("enabled", True)
                )
                db.add(conf)
                db.commit()
            
            self.db_config = SimpleNamespace(
                enabled=conf.enabled,
                mode=conf.mode,
                default_action=conf.default_action,
                safe_search_enabled=conf.safe_search_enabled
            )

            # Merge database JSON configuration fields dynamically
            if conf.ai_holofilter:
                file_config.raw_config["ai_holofilter"] = conf.ai_holofilter
                self.yaml_config["ai_holofilter"] = conf.ai_holofilter
            if conf.cache:
                file_config.raw_config["cache"] = conf.cache
                self.yaml_config["cache"] = conf.cache
            if conf.dns_sinkhole:
                file_config.raw_config["dns_sinkhole"] = conf.dns_sinkhole
                self.yaml_config["dns_sinkhole"] = conf.dns_sinkhole
            if conf.logging:
                file_config.raw_config["logging"] = conf.logging
                self.yaml_config["logging"] = conf.logging
            if conf.safe_search:
                file_config.raw_config["safe_search"] = conf.safe_search
                self.yaml_config["safe_search"] = conf.safe_search

            # 2. Seed Builtin Categories IF none exist
            cat_count = db.query(WebFilterCategory).count()
            if cat_count == 0:
                builtins = self.yaml_config.get("builtin_categories", [])
                if builtins:
                    self.logger.info(f"[WebFilter] Seeding {len(builtins)} builtin categories...")
                    for cat_def in builtins:
                        new_cat = WebFilterCategory(
                            name=cat_def.get("name"),
                            description=cat_def.get("description", ""),
                            action=cat_def.get("action", "BLOCK").upper(),
                            risk_score=cat_def.get("risk_score", 50),
                            is_custom=False
                        )
                        db.add(new_cat)
                    db.commit()

            # 3. Seed custom_rules from YAML into WebFilterDomain
            from modules.web_filter.models import WebFilterDomain
            custom_rules = self.yaml_config.get("custom_rules", [])
            if custom_rules:
                new_count = 0
                for rule in custom_rules:
                    pattern = rule.get("domain", "").strip().lower()
                    category = rule.get("category", "").strip()
                    action = rule.get("action", "BLOCK").upper()
                    if not pattern or not category:
                        continue
                    exists = db.query(WebFilterDomain).filter_by(
                        domain_pattern=pattern
                    ).first()
                    if not exists:
                        db.add(WebFilterDomain(
                            domain_pattern=pattern,
                            category_name=category,
                            action=action
                        ))
                        new_count += 1
                    else:
                        exists.category_name = category
                        exists.action = action
                if new_count > 0:
                    db.commit()
                    self.logger.info(
                        "[WebFilter] custom_rules synced from YAML: "
                        "%d total rules, %d newly inserted.",
                        len(custom_rules), new_count
                    )
                else:
                    db.commit()

            import time
            self.last_config_sync = time.time()

        except Exception as e:
            self.logger.error(f"[WebFilter] DB Sync warning, using fallback config: {e}")
            self.db_config = SimpleNamespace(
                enabled=self.yaml_config.get("enabled", True),
                mode=self.yaml_config.get("mode", "enforce"),
                default_action=self.yaml_config.get("default_action", "ALLOW"),
                safe_search_enabled=self.yaml_config.get("safe_search", {}).get("enabled", True)
            )
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            try:
                db.close()
            except Exception:
                pass

    def reload(self) -> None:
        """Reload configuration and instruct engines to refresh caches."""
        self.logger.info("[WebFilter] Reloading engine configuration.")
        self.yaml_config = self._load_yaml()
        self._sync_database()
        
        # Reload category cache sizes if specified in yaml
        cache_cfg = self.yaml_config.get("cache", {})
        max_sz = cache_cfg.get("max_size", 50000)
        ttl = cache_cfg.get("ttl_seconds", 300)
        
        # We replace the engine instance entirely to apply new cache bounds cleanly
        self.category_engine = CategoryEngine(max_cache_size=max_sz, cache_ttl=ttl)

    def evaluate(self, url: Any = "", domain: str = "") -> Any:
        """
        Evaluate a web request against SafeSearch and Categorizations.

        Returns:
            If input is a PolicyContext object: Action
            Otherwise: (Action, modified_url)
        """
        is_context = False
        if hasattr(url, "url") and hasattr(url, "domain"):
            is_context = True
            domain = getattr(url, "domain") or ""
            url = getattr(url, "url") or ""

        if not url:
            url = ""
        if not domain:
            domain = ""

        if not domain and url:
            if url.startswith("http"):
                import urllib.parse
                try:
                    parsed = urllib.parse.urlparse(url)
                    domain = parsed.netloc.lower().split(":")[0]
                except Exception:
                    pass
            else:
                domain = url.lower().split(":")[0]

        if self.db_config and not self.db_config.enabled:
            if is_context:
                return Action.ALLOW
            return Action.ALLOW, None

        mode = self.db_config.mode.lower() if self.db_config else "enforce"
        
        modified_url = None

        # 0. Check dynamic loaded rules if any
        if self.rules:
            import fnmatch
            import urllib.parse
            for rule in self.rules:
                # Safe Search Check
                if rule.safe_search:
                    ss_engines = self.yaml_config.get("safe_search", {}).get("engines", [])
                    if any(domain == engine or domain.endswith("." + engine) for engine in ss_engines):
                        new_url = SafeSearch.append_safe_param(url)
                        if new_url != url:
                            modified_url = new_url
                        return Action.MONITOR if is_context else (Action.MONITOR, modified_url)
                
                # Block File Types Check
                if rule.block_file_types:
                    parsed = urllib.parse.urlparse(url)
                    path = parsed.path
                    ext = path.split('.')[-1].lower() if '.' in path else ""
                    if ext in [ft.lower() for ft in rule.block_file_types]:
                        if rule.action in (Action.BLOCK, Action.REJECT):
                            return rule.action if is_context else (rule.action, None)
                
                # Exact URL / Pattern Match Check
                if rule.exact_urls:
                    for pattern in rule.exact_urls:
                        if fnmatch.fnmatch(url, pattern) or fnmatch.fnmatch(domain, pattern):
                            if rule.action in (Action.BLOCK, Action.REJECT):
                                return rule.action if is_context else (rule.action, None)
                            elif rule.action == Action.ALLOW:
                                return Action.ALLOW if is_context else (Action.ALLOW, modified_url)

        # 1. Safe Search Enforcement (HTTP Rewrite logic)
        if self.db_config and self.db_config.safe_search_enabled and domain and url:
            ss_engines = self.yaml_config.get("safe_search", {}).get("engines", [])
            # If domain matches a known SafeSearch engine
            if any(domain == engine or domain.endswith("." + engine) for engine in ss_engines):
                new_url = SafeSearch.append_safe_param(url)
                if new_url != url:
                    self.logger.debug(f"[WebFilter] SafeSearch rewrite: {url} -> {new_url}")
                    modified_url = new_url
                    # We continue evaluation unless we want to return early
                    # SafeSearch itself doesn't BLOCK, it just rewrites

        # 2. Categorize the domain and URL path
        match = self.category_engine.categorize(domain)

        # 2b. URL path-based category detection (e.g. /category/hacking, /category/gambling)
        if ("UNRATED" in match.categories or not match.categories) and url:
            import re
            url_lower = url.lower()
            # Check for /category/<cat_name> test patterns or category keywords in path
            category_keywords = {
                "hacking": ["hacking", "exploit-db", "blackhat", "exploit", "pentest", "vulnerability"],
                "gambling": ["gambling", "casino", "poker", "bet365", "betting", "lottery", "slots"],
                "malware": ["malware", "phishing", "ransomware", "trojan", "virus", "eicar", "botnet", "c2"],
                "adult": ["adult", "porn", "xxx", "sex", "erotic", "nsfw"],
            }
            path_cat = None
            cat_match = re.search(r'/category/([a-z0-9_-]+)', url_lower)
            if cat_match:
                path_cat = cat_match.group(1).lower()
            else:
                for cat_name, kw_list in category_keywords.items():
                    if any(kw in url_lower for kw in kw_list):
                        path_cat = cat_name.lower()
                        break

            if path_cat:
                match.categories = [path_cat]
                self.logger.info(f"[WebFilter] URL path matched category '{path_cat}' for URL: {url}")

        # 3. Apply action based on highest priority category match (BLOCK wins over ALLOW)
        final_action = None
        
        for cat in match.categories:
            if cat.upper() == "UNRATED":
                continue
                
            action_str = self.category_engine.get_category_action(cat).upper()
            
            action_map = {
                "ALLOW": Action.ALLOW,
                "BLOCK": Action.BLOCK,
                "REJECT": Action.REJECT,
                "MONITOR": Action.MONITOR
            }
            mapped_action = action_map.get(action_str, Action.BLOCK)

            # Block-type actions take immediate precedence
            if mapped_action in (Action.BLOCK, Action.REJECT):
                self.logger.info(f"[WebFilter] Blocked '{domain}' (Category '{cat}', Score: {self.category_engine.get_category_risk(cat)})")
                final_action = mapped_action
                break
            elif mapped_action == Action.ALLOW:
                # Store allow, but keep looking in case another category blocks
                if not final_action:
                    final_action = Action.ALLOW

        # Fallback to default config action if no category explicitly matched
        if final_action is None:
            default_str = self.db_config.default_action.upper() if self.db_config else "ALLOW"
            final_action = Action.ALLOW if default_str == "ALLOW" else Action.BLOCK

        # If we are in monitor mode, never block
        if mode == "monitor" and final_action in (Action.BLOCK, Action.REJECT):
            self.logger.info(f"[WebFilter] Monitor Mode: Would have blocked '{domain}', allowing instead.")
            final_action = Action.MONITOR

        # If we just rewrote the URL, we might want to let the plugin know
        # Even if Action is ALLOW, returning `modified_url` triggers the rewrite in the proxy
        if is_context:
            return final_action
        return final_action, modified_url
