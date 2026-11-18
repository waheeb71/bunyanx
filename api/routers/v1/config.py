"""
Enterprise bunyanx - Configuration Management Endpoints
GET    /api/v1/config                       — Read full config  (admin)
PUT    /api/v1/config                       — Update a key      (admin)
POST   /api/v1/config/reset                 — Reset to default  (admin)
GET    /api/v1/config/modules               — List module state (operator+)
GET    /api/v1/config/modules/stats         — Per-module event counts (operator+)
PUT    /api/v1/modules/{name}/toggle        — Enable/disable a module (admin)
GET    /api/v1/config/current               — Merged active config (admin)
GET    /api/v1/config/versions              — List snapshots (admin)
GET    /api/v1/config/diff                  — Diff two versions (admin)
POST   /api/v1/config/rollback              — Roll back to version (admin)
POST   /api/v1/config/reload                — Force hot-reload (admin)
POST   /api/v1/config/snapshot              — Manual snapshot (admin)

FIX (2026-06-21): Merged two router definitions that were shadowing each other.
                  Added require_admin / require_operator to ALL endpoints.
"""
import os
import logging
from typing import Any
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field

from api.core.auth import require_admin, require_operator

# ── Single router for the entire config surface ───────────────────────────────
router = APIRouter(prefix="/api/v1", tags=["Configuration"])
logger = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ConfigUpdate(BaseModel):
    category: str = Field(..., description="Top-level YAML section (e.g. 'proxy', 'ml')")
    key: str = Field(..., description="Key within the section")
    value: Any = Field(..., description="New value")


class ModuleToggle(BaseModel):
    enabled: bool


# ── File helpers ──────────────────────────────────────────────────────────────

def _config_path(filename: str = "base.yaml") -> Path:
    base_dir = Path(__file__).parent.parent.parent.parent / "system" / "config"
    target_path = base_dir / filename
    if not str(target_path.resolve()).startswith(str(base_dir.resolve())):
        raise ValueError("Invalid configuration file path.")
    return target_path


def _read_config(filename: str = "base.yaml") -> dict:
    path = _config_path(filename)
    if not path.exists():
        return {}

    if filename.endswith(".conf"):
        data = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    val = v.strip()
                    if val.isdigit():
                        val = int(val)
                    data[k.strip()] = val
        return {"sysctl": data}

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_config(data: dict, filename: str = "base.yaml"):
    path = _config_path(filename)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


def _write_config_conf(update_key: str, update_val: Any, filename: str):
    path = _config_path(filename)
    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    found = False
    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith("#") and "=" in line:
            k, _ = line.split("=", 1)
            if k.strip() == update_key:
                lines[i] = f"{k.strip()} = {update_val}\n"
                found = True
                break

    if not found:
        lines.append(f"{update_key} = {update_val}\n")

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _hot_reload(request: Request):
    """Trigger config reload on the running engine if available."""
    try:
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and hasattr(bunyanx, "reload_config"):
            bunyanx.reload_config()
    except Exception as e:
        logger.warning(f"Hot-reload skipped: {e}")


# ── Core Config CRUD ──────────────────────────────────────────────────────────

@router.get("/config")
async def get_config(
    request: Request,
    file: str = "base.yaml",
    token: dict = Depends(require_admin),
):
    """Return the full system configuration from a specific file. Admin only."""
    try:
        return _read_config(file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config read error: {e}")


@router.put("/config")
async def update_config(
    request: Request,
    update: ConfigUpdate,
    file: str = "base.yaml",
    token: dict = Depends(require_admin),
):
    """Update a single configuration key in a specific file and hot-reload the engine. Admin only."""
    try:
        if file.endswith(".conf"):
            _write_config_conf(update.key, update.value, file)
            return {"status": "success", "updated": f"sysctl.{update.key}", "file": file}

        cfg = _read_config(file)
        cfg.setdefault(update.category, {})
        section = cfg[update.category]
        if isinstance(section, dict) and isinstance(update.value, dict):
            section.setdefault(update.key, {}).update(update.value)
        else:
            cfg[update.category][update.key] = update.value
        _write_config(cfg, file)
        _hot_reload(request)
        return {"status": "success", "updated": f"{update.category}.{update.key}", "file": file}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config update error: {e}")


@router.post("/config/reset")
async def reset_config(
    request: Request,
    file: str = "base.yaml",
    token: dict = Depends(require_admin),
):
    """Reset a specific configuration file to its factory default. Admin only."""
    import shutil
    try:
        path = _config_path(file)

        parts = file.rsplit(".", 1)
        if len(parts) == 2:
            default_file = f"{parts[0]}.default.{parts[1]}"
        else:
            default_file = f"{file}.default"

        default_path = _config_path(default_file)

        if not default_path.exists():
            raise HTTPException(status_code=404, detail="Default configuration backup not found.")

        shutil.copyfile(default_path, path)
        _hot_reload(request)
        return {"status": "success", "message": f"{file} has been restored to default settings."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset config: {e}")


# ── Module Listing & Toggle ───────────────────────────────────────────────────

@router.get("/config/modules")
async def list_modules(token: dict = Depends(require_operator)):
    """Return the enabled/disabled state of every module. Operator+ only."""
    try:
        cfg = _read_config()
        return cfg.get("modules", {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list modules: {e}")


@router.get("/config/modules/stats")
async def get_module_stats(
    request: Request,
    token: dict = Depends(require_operator),
):
    """
    Return per-module event counts and last detection timestamp
    sourced from the SecurityEvent database table. Operator+ only.
    """
    try:
        from system.database.database import SecurityEvent
        from sqlalchemy import func
        from sqlalchemy.future import select

        bunyanx = getattr(request.app.state, "bunyanx", None)
        if not bunyanx:
            return {}

        async with bunyanx.db.session() as session:
            stmt = (
                select(
                    SecurityEvent.event_type,
                    func.count(SecurityEvent.id).label("event_count"),
                    func.max(SecurityEvent.timestamp).label("last_seen"),
                )
                .group_by(SecurityEvent.event_type)
            )
            result = await session.execute(stmt)
            rows = result.all()

        stats = {}
        for row in rows:
            stats[row.event_type] = {
                "event_count": row.event_count,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }

        return stats

    except RuntimeError:
        return {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch module stats: {e}")


@router.put("/modules/{module_name}/toggle")
async def toggle_module(
    request: Request,
    module_name: str,
    toggle: ModuleToggle,
    token: dict = Depends(require_admin),
):
    """
    Enable or disable an inspection module dynamically.
    Triggers an immediate hot-reload of the plugin pipeline. Admin only.
    """
    try:
        cfg = _read_config()
        cfg.setdefault("modules", {}).setdefault(module_name, {})
        cfg["modules"][module_name]["enabled"] = toggle.enabled
        _write_config(cfg)

        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and hasattr(bunyanx, "inspection_pipeline"):
            from system.core.module_manager import ModuleManager
            pipeline = bunyanx.inspection_pipeline
            for p in list(pipeline._plugins_by_name.keys()):
                pipeline.unregister_plugin(p)
            ModuleManager(cfg, pipeline).load_plugins()
            logger.info(f"Plugin pipeline reloaded after toggling '{module_name}'")

        # Write AuditLog
        try:
            from system.database.database import AuditLog
            action_str = "enabled" if toggle.enabled else "disabled"
            async with bunyanx.db.session() as session:
                session.add(AuditLog(
                    username=token.get("sub", "unknown"),
                    action=f"module_toggle:{module_name}:{action_str}",
                    resource="config",
                    details={"module": module_name, "enabled": toggle.enabled},
                ))
                await session.commit()
        except Exception:
            pass

        action = "enabled" if toggle.enabled else "disabled"
        return {"status": "success", "message": f"Module '{module_name}' is now {action}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Toggle failed: {e}")


# ── Config Versioning (previously unprotected — NOW REQUIRES AUTH) ────────────

@router.get("/config/current")
async def get_current_config(token: dict = Depends(require_admin)):
    """Return the merged active configuration (base.yaml + features.yaml + ENV). Admin only."""
    from system.config.config_manager import ConfigManager
    return ConfigManager.instance().get_all()


@router.get("/config/versions")
async def list_versions(token: dict = Depends(require_admin)):
    """List all configuration snapshots (latest first). Admin only."""
    from system.config.config_manager import ConfigManager
    snapshots = ConfigManager.instance().list_snapshots()
    return {"total": len(snapshots), "versions": snapshots}


@router.get("/config/diff")
async def diff_versions(
    v1: str = Query(..., description="Version ID A (e.g. 'v3')"),
    v2: str = Query(..., description="Version ID B (e.g. 'v7')"),
    token: dict = Depends(require_admin),
):
    """Compare two config versions and return a JSON diff. Admin only."""
    from system.config.config_manager import ConfigManager
    diff = ConfigManager.instance().diff(v1, v2)
    if "error" in diff:
        raise HTTPException(status_code=404, detail=diff["error"])
    return {"v1": v1, "v2": v2, "diff": diff, "changed_keys": list(diff.keys())}


@router.post("/config/rollback")
async def rollback_config(
    version: str = Query(..., description="Version ID to roll back to"),
    token: dict = Depends(require_admin),
):
    """Roll back to a previous configuration version. Admin only."""
    from system.config.config_manager import ConfigManager
    success = ConfigManager.instance().rollback(version)
    if not success:
        raise HTTPException(status_code=404, detail=f"Version '{version}' not found")
    return {"status": "rolled_back", "version": version}


@router.post("/config/reload")
async def reload_config(token: dict = Depends(require_admin)):
    """Force hot-reload of base.yaml + features.yaml from disk. Admin only."""
    from system.config.config_manager import ConfigManager
    diff = ConfigManager.instance().force_reload()
    return {
        "status": "reloaded",
        "changed_keys": list(diff.keys()),
        "changes": diff,
    }


@router.post("/config/snapshot")
async def take_snapshot(token: dict = Depends(require_admin)):
    """Manually take a config snapshot (useful before making changes). Admin only."""
    from system.config.config_manager import ConfigManager
    version_id = ConfigManager.instance().snapshot(source="api")
    return {"status": "created", "version_id": version_id}


# ── ML Core Configuration Endpoints ──────────────────────────────────────────

@router.get("/ml-core/config")
async def get_ml_core_config(token: dict = Depends(require_operator)):
    """Return ML core engine configuration parameters."""
    try:
        cfg = _read_config("base.yaml")
        ml_sec = cfg.get("ml_core") or cfg.get("ml") or {}
        return {
            "correlation_threshold": float(ml_sec.get("correlation_threshold", ml_sec.get("anomaly_detection", {}).get("threshold", 0.85))),
            "time_window_seconds": int(ml_sec.get("time_window_seconds", 300)),
            "enable_deep_learning": bool(ml_sec.get("enable_deep_learning", ml_sec.get("enabled", True))),
            "enable_gpu": bool(ml_sec.get("enable_gpu", False)),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ML core config: {e}")


@router.put("/ml-core/config")
async def update_ml_core_config(
    request: Request,
    new_cfg: dict,
    token: dict = Depends(require_admin),
):
    """Update ML core engine configuration parameters in base.yaml."""
    try:
        cfg = _read_config("base.yaml")
        ml_sec = cfg.setdefault("ml_core", {})
        if "correlation_threshold" in new_cfg:
            ml_sec["correlation_threshold"] = float(new_cfg["correlation_threshold"])
        if "time_window_seconds" in new_cfg:
            ml_sec["time_window_seconds"] = int(new_cfg["time_window_seconds"])
        if "enable_deep_learning" in new_cfg:
            ml_sec["enable_deep_learning"] = bool(new_cfg["enable_deep_learning"])
        if "enable_gpu" in new_cfg:
            ml_sec["enable_gpu"] = bool(new_cfg["enable_gpu"])
        _write_config(cfg, "base.yaml")
        _hot_reload(request)
        return {"status": "success", "config": ml_sec}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ML core config: {e}")

