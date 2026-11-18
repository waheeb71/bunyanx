"""
bunyanx NGFW — Config Manager v2
=====================================
Versioned, hot-reloadable configuration with rollback support.

Priority (highest → lowest):
  1. Environment variables
  2. features.yaml / base.yaml (watched, hot-reload)
  3. Defaults

Features:
  ✅ Hot reload on file change (no restart)
  ✅ Versioned snapshots (rollback)
  ✅ JSON diff between versions
  ✅ API endpoints: /config/versions, /config/diff, /config/rollback

Usage:
    cfg = ConfigManager.instance()
    val = cfg.get("firewall.default_action", default="BLOCK")
    snapshot_id = cfg.snapshot()
    await cfg.rollback(snapshot_id)
"""

import copy
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, ConfigDict

class ConfigSchema(BaseModel):
    """
    Pydantic schema for core config validation.

    extra='ignore' — unknown top-level keys are silently dropped so that
    config files with experimental or future keys don't crash the system,
    but they are also not silently passed through where they might mask
    typos. To enforce strict validation in production, change to 'forbid'.
    """
    model_config = ConfigDict(extra='ignore')
    firewall: dict = Field(default_factory=dict)
    modules: dict = Field(default_factory=dict)
    system: dict = Field(default_factory=dict)
    proxy: dict = Field(default_factory=dict)
    tls: dict = Field(default_factory=dict)
    security: dict = Field(default_factory=dict)
    monitoring: dict = Field(default_factory=dict)
    api: dict = Field(default_factory=dict)
    integration: dict = Field(default_factory=dict)
    ha: dict = Field(default_factory=dict)
    vpn: dict = Field(default_factory=dict)
    ml: dict = Field(default_factory=dict)
    ebpf: dict = Field(default_factory=dict)
    routing: dict = Field(default_factory=dict)
    flow_tracking: dict = Field(default_factory=dict)
    ssl_inspection: dict = Field(default_factory=dict)
    interfaces: dict = Field(default_factory=dict)
    ai_enforcement: dict = Field(default_factory=dict)
    features: dict = Field(default_factory=dict)
    database: dict = Field(default_factory=dict)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Config Snapshot
# ──────────────────────────────────────────────────────────────────────

class ConfigSnapshot:
    def __init__(self, version_id: str, data: dict, source: str = "auto"):
        self.version_id  = version_id
        self.data        = copy.deepcopy(data)
        self.created_at  = datetime.now(timezone.utc).isoformat()
        self.source      = source    # "auto" | "api" | "cli"

    def to_dict(self) -> dict:
        return {
            "version_id":  self.version_id,
            "created_at":  self.created_at,
            "source":      self.source,
        }


# ──────────────────────────────────────────────────────────────────────
# Config Manager
# ──────────────────────────────────────────────────────────────────────

class ConfigManager:
    """
    Singleton versioned config manager.

    Merges:
      - ENV variables (prefix NGFW_)
      - base.yaml
      - features.yaml

    Thread-safe for concurrent read-heavy workloads.
    Snapshots stored in-memory (last 50 versions).
    """

    _instance: Optional["ConfigManager"] = None
    _lock = threading.RLock()
    MAX_SNAPSHOTS = 50

    def __init__(self, config_dir: Optional[Path] = None):
        self._dir = config_dir or Path(__file__).parent
        self._data: dict = {}
        self._snapshots: List[ConfigSnapshot] = []
        self._rw_lock = threading.RLock()
        self._version_counter = 0
        self._reload_callbacks: list = []
        self._watched_files = {self._dir / "base.yaml", self._dir / "features.yaml"}
        self._observer = None

        self._load_and_merge()

        self._start_watcher()
        logger.info("[ConfigManager] Started ✓")

    # ── Singleton ──────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "ConfigManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Public API ─────────────────────────────────────────────────

    def get(self, dot_path: str, default: Any = None) -> Any:
        """
        Read a config value by dot-notation path.
        Example: cfg.get("firewall.rules.default_action", "BLOCK")
        """
        with self._rw_lock:
            obj = self._data
            for key in dot_path.split("."):
                if not isinstance(obj, dict) or key not in obj:
                    return default
                obj = obj[key]
            return obj

    def get_all(self) -> dict:
        with self._rw_lock:
            return copy.deepcopy(self._data)

    def snapshot(self, source: str = "api") -> str:
        """Take a named snapshot of the current config. Returns version_id."""
        with self._rw_lock:
            snap = self._make_snapshot(source)
        logger.info(f"[ConfigManager] Snapshot created: {snap.version_id}")
        return snap.version_id

    def rollback(self, version_id: str) -> bool:
        """
        Restore config to a previous snapshot.
        Returns True on success, False if version not found.
        """
        with self._rw_lock:
            target = next((s for s in self._snapshots if s.version_id == version_id), None)
            if target is None:
                logger.warning(f"[ConfigManager] Snapshot not found: {version_id}")
                return False

            # Take a snapshot of current before rollback
            self._make_snapshot("pre-rollback")
            self._data = copy.deepcopy(target.data)
            logger.info(f"[ConfigManager] Rolled back to: {version_id}")
            self._notify_callbacks()
            return True

    def list_snapshots(self) -> List[dict]:
        with self._rw_lock:
            return [s.to_dict() for s in reversed(self._snapshots)]

    def diff(self, version_id_a: str, version_id_b: str) -> dict:
        """Compare two snapshots and return a human-readable diff."""
        with self._rw_lock:
            snap_a = next((s for s in self._snapshots if s.version_id == version_id_a), None)
            snap_b = next((s for s in self._snapshots if s.version_id == version_id_b), None)

        if not snap_a or not snap_b:
            return {"error": "One or both versions not found"}

        return self._compute_diff(snap_a.data, snap_b.data)

    def force_reload(self) -> dict:
        """Force immediate reload from disk (for API endpoint use)."""
        old = copy.deepcopy(self._data)
        self._load_and_merge()
        diff = self._compute_diff(old, self._data)
        logger.info(f"[ConfigManager] Force-reloaded. Changes: {list(diff.keys())}")
        return diff

    def on_reload(self, callback) -> None:
        self._reload_callbacks.append(callback)

    # ── Internal ───────────────────────────────────────────────────

    def _load_and_merge(self) -> None:
        """Merge all config sources in priority order."""
        merged: dict = {}

        # 1. Load base.yaml (lowest priority file)
        base_path = self._dir / "base.yaml"
        if base_path.exists():
            try:
                with open(base_path, encoding="utf-8") as f:
                    base = yaml.safe_load(f) or {}
                merged = self._deep_merge(merged, base)
            except Exception as exc:
                logger.error(f"[ConfigManager] Failed to load base.yaml: {exc}")

        # 2. Load features.yaml
        features_path = self._dir / "features.yaml"
        if features_path.exists():
            try:
                with open(features_path, encoding="utf-8") as f:
                    features = yaml.safe_load(f) or {}
                merged = self._deep_merge(merged, features)
            except Exception as exc:
                logger.error(f"[ConfigManager] Failed to load features.yaml: {exc}")

        # 2.5 Load module-specific configurations
        modules_conf = merged.get("modules", {})
        base_ngfw_dir = self._dir.parent.parent
        for mod_name, mod_info in modules_conf.items():
            if isinstance(mod_info, dict) and mod_info.get("enabled", False):
                config_path = mod_info.get("config_path")
                if config_path:
                    abs_path = base_ngfw_dir / config_path
                    if abs_path.exists():
                        self._watched_files.add(abs_path)
                        try:
                            with open(abs_path, 'rb') as f:
                                raw_bytes = f.read()
                            
                            content = None
                            if raw_bytes.startswith(b'\xff\xfe'):
                                content = raw_bytes.decode('utf-16le')
                            elif raw_bytes.startswith(b'\xfe\xff'):
                                content = raw_bytes.decode('utf-16be')
                            elif raw_bytes.startswith(b'\xef\xbb\xbf'):
                                content = raw_bytes.decode('utf-8-sig')
                            else:
                                try:
                                    content = raw_bytes.decode('utf-8')
                                except UnicodeDecodeError:
                                    content = raw_bytes.decode('cp1256', errors='ignore')
                            
                            mod_data = yaml.safe_load(content) or {}
                            
                            # Smart unwrap: if the yaml file defines a root key matching the module name,
                            # unwrap it so we don't get nested structures (e.g. modules.waf.waf)
                            data_to_merge = {}
                            for k, v in mod_data.items():
                                if k == mod_name and isinstance(v, dict):
                                    data_to_merge = self._deep_merge(data_to_merge, v)
                                else:
                                    data_to_merge[k] = v
                                    
                            merged["modules"][mod_name] = self._deep_merge(merged["modules"][mod_name], data_to_merge)
                        except Exception as exc:
                            logger.error(f"[ConfigManager] Failed to load module config {abs_path}: {exc}")

        # 3. Override with ENV variables (NGFW_ prefix)
        for key, value in os.environ.items():
            if key.startswith("NGFW_"):
                dot_key = key[5:].lower().replace("__", ".")
                try:
                    parsed_val = yaml.safe_load(value)
                except Exception:
                    parsed_val = value
                self._set_nested(merged, dot_key, parsed_val)

        with self._rw_lock:
            try:
                validated = ConfigSchema(**merged)
                self._data = validated.model_dump(mode='json')
                self._make_snapshot("auto-load")
            except Exception as e:
                logger.error(f"[ConfigManager] Configuration validation failed: {e}. Changes rejected.")
                return

        self._notify_callbacks()

    def _make_snapshot(self, source: str = "auto") -> ConfigSnapshot:
        self._version_counter += 1
        snap = ConfigSnapshot(
            version_id=f"v{self._version_counter}",
            data=self._data,
            source=source,
        )
        self._snapshots.append(snap)
        # Keep only last MAX_SNAPSHOTS
        if len(self._snapshots) > self.MAX_SNAPSHOTS:
            self._snapshots = self._snapshots[-self.MAX_SNAPSHOTS:]
        return snap

    def _start_watcher(self) -> None:
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class ConfigHandler(FileSystemEventHandler):
                def __init__(self, manager):
                    self.manager = manager
                    
                def on_modified(self, event):
                    if not event.is_directory:
                        path_str = str(Path(event.src_path).resolve())
                        watched_strs = {str(f.resolve()) for f in self.manager._watched_files}
                        if path_str in watched_strs:
                            logger.info(f"[ConfigManager] Detected change in {event.src_path}")
                            self.manager._load_and_merge()
                            logger.info("[ConfigManager] Hot-reloaded ✓")

            event_handler = ConfigHandler(self)
            self._observer = Observer()
            
            # Watch system config dir
            self._observer.schedule(event_handler, path=str(self._dir), recursive=False)
            
            # Watch modules dir recursively so we catch changes to module configs
            modules_dir = self._dir.parent.parent / "modules"
            if modules_dir.exists():
                self._observer.schedule(event_handler, path=str(modules_dir), recursive=True)
                
            self._observer.start()
        except ImportError:
            logger.warning("Watchdog not installed. Falling back to simple polling.")
            self._watcher = threading.Thread(
                target=self._watch_loop,
                name="ConfigManager-Watcher",
                daemon=True,
            )
            self._watcher.start()

    def _watch_loop(self) -> None:
        last_mtimes: Dict[Path, float] = {}

        while True:
            time.sleep(5)
            changed = False
            for f in list(self._watched_files):
                try:
                    mtime = f.stat().st_mtime
                    if mtime != last_mtimes.get(f, 0.0):
                        # Only trigger reload if this isn't the first time we've seen it
                        if f in last_mtimes:
                            changed = True
                            logger.info(f"[ConfigManager] Detected change in {f.name}")
                        last_mtimes[f] = mtime
                except FileNotFoundError:
                    pass

            if changed:
                self._load_and_merge()
                logger.info("[ConfigManager] Hot-reloaded ✓")

    def _notify_callbacks(self) -> None:
        for cb in self._reload_callbacks:
            try:
                cb(self._data)
            except Exception as exc:
                logger.warning(f"[ConfigManager] Callback error: {exc}")

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    @staticmethod
    def _set_nested(d: dict, dot_key: str, value: str) -> None:
        keys = dot_key.split(".")
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value

    @staticmethod
    def _compute_diff(a: dict, b: dict, prefix: str = "") -> dict:
        diff: dict = {}
        all_keys = set(a.keys()) | set(b.keys())
        for key in all_keys:
            full_key = f"{prefix}.{key}" if prefix else key
            va, vb = a.get(key), b.get(key)
            if isinstance(va, dict) and isinstance(vb, dict):
                nested = ConfigManager._compute_diff(va, vb, full_key)
                diff.update(nested)
            elif va != vb:
                diff[full_key] = {"before": va, "after": vb}
        return diff
