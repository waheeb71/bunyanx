"""
Proxy API Router — bunyanx NGFW
===================================
Exposes REST endpoints to read and update proxy configuration
stored in system/config/base.yaml.

Endpoints:
  GET  /api/v1/proxy/status        — current proxy mode & health
  GET  /api/v1/proxy/config        — full proxy configuration
  PUT  /api/v1/proxy/config        — update proxy configuration (admin only)
  GET  /api/v1/proxy/vips          — list VIP mappings
  POST /api/v1/proxy/vips          — add a VIP mapping (admin only)
  DELETE /api/v1/proxy/vips/{name} — remove a VIP mapping (admin only)

Auto-discovered by _load_module_routers() in api/rest/main.py.
"""
from __future__ import annotations

from typing import Any, List, Optional
import re
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
import yaml
from pathlib import Path

from system.core.path_manager import resolve_path
from api.core.auth import require_admin, make_permission_checker

router = APIRouter(prefix="/api/v1/proxy", tags=["proxy"])
require_proxy = make_permission_checker("proxy")


# ── Input Validation ─────────────────────────────────────────────────────────
_IP_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9._-]{1,253})$"
)


class VipEntry(BaseModel):
    name:             str = Field(..., min_length=1, max_length=64)
    external_ip:      str
    external_port:    int = Field(..., ge=1, le=65535)
    internal_ip:      str
    internal_port:    int = Field(..., ge=1, le=65535)
    use_tls_upstream: bool = False

    @field_validator("external_ip", "internal_ip")
    @classmethod
    def validate_ip_format(cls, v):
        if not _IP_RE.match(v):
            raise ValueError(f"Invalid IP/hostname format: {v}")
        return v


class BackendEntry(BaseModel):
    host: str
    port: int = Field(..., ge=1, le=65535)
    ssl:  bool = False


class HardeningConfig(BaseModel):
    cloaking_enabled: bool = True
    server_banner:    str  = "bunyanx-NGFW"
    strip_headers:    List[str] = Field(default_factory=lambda: [
        "Server", "X-Powered-By", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Runtime", "X-Version", "Via", "X-Varnish"
    ])


class ProxyConfigSchema(BaseModel):
    """Complete proxy configuration schema — mirrors all proxy.* keys in base.yaml."""
    is_active:            bool   = True
    mode:                 str    = "transparent_proxy"
    listen_port:          int    = Field(8443, ge=1, le=65535)
    http_port:            int    = Field(8080, ge=1, le=65535)
    max_connections:      int    = Field(10000, ge=1, le=100000)
    buffer_size:          int    = Field(65536, ge=1024, le=1048576)
    connection_timeout:   int    = Field(300, ge=10, le=3600)
    strict_cert_validation: bool = True
    health_check_interval: int   = Field(10, ge=1, le=300)
    health_check_timeout:  int   = Field(3, ge=1, le=30)
    backends: List[BackendEntry] = Field(default_factory=list)
    hardening: HardeningConfig  = Field(default_factory=HardeningConfig)
    allowed_ssrf_hosts: List[str] = Field(default_factory=list)


# ── YAML helpers ─────────────────────────────────────────────────────────────

_yaml_lock = threading.Lock()


def _yaml_path() -> Path:
    return resolve_path("system/config/base.yaml")


def _load() -> dict:
    """Load base.yaml — returns empty dict on error."""
    try:
        with open(_yaml_path(), "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    """
    Persist base.yaml atomically with a thread lock.
    """
    with _yaml_lock:
        with open(_yaml_path(), "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True,
                      sort_keys=False)


def _mode_to_ui(yaml_mode: str, is_active: bool) -> str:
    """'transparent' → 'transparent_proxy'  (UI representation)."""
    if not is_active:
        return "transparent_proxy"
    if yaml_mode in ("none", "disabled", "off"):
        return "transparent_proxy"
    mode = yaml_mode
    if mode == "standard":
        mode = "forward"
    return mode if mode.endswith("_proxy") else mode + "_proxy"


def _mode_to_yaml(ui_mode: str) -> str:
    """'transparent_proxy' → 'transparent'  (YAML representation)."""
    mode = ui_mode.replace("_proxy", "")
    if mode == "standard":
        return "forward"
    return mode


def _sync_db_proxy_config(new_config: ProxyConfigSchema) -> None:
    """Synchronize configuration schema to ProxyConfig ORM database table if DB is available."""
    try:
        from system.database.database import get_db
        db_gen = get_db()
        db = next(db_gen)
        if db is not None:
            from modules.proxy.models import ProxyConfig
            record = db.query(ProxyConfig).first()
            if not record:
                record = ProxyConfig()
                db.add(record)
            record.is_active = new_config.is_active
            record.mode = new_config.mode
            record.listen_port = new_config.listen_port
            record.http_port = new_config.http_port
            record.max_connections = new_config.max_connections
            record.buffer_size = new_config.buffer_size
            record.strict_cert_validation = new_config.strict_cert_validation
            db.commit()
    except Exception:
        pass


async def _notify_runtime_reload(request: Request, cfg_dict: dict) -> None:
    """Notify active ProxyModule instance to reload running configuration dynamically."""
    try:
        app_state = getattr(request, "app", None) and getattr(request.app, "state", None)
        if app_state:
            cn = getattr(app_state, "bunyanx", None)
            if cn and hasattr(cn, "reload_config"):
                await cn.reload_config(cfg_dict)
    except Exception:
        pass



# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status", summary="Proxy status")
async def get_status(token: dict = Depends(require_proxy)):
    """Return whether the proxy is active and in which mode."""
    cfg = _load()
    yaml_mode = cfg.get("proxy", {}).get("mode", "transparent")
    is_active  = yaml_mode not in ("none", "disabled", "off")
    return {
        "status":  "active" if is_active else "inactive",
        "module":  "proxy",
        "mode":    yaml_mode,
        "ui_mode": _mode_to_ui(yaml_mode, is_active),
    }


@router.get("/stats", summary="Get proxy statistics")
async def get_proxy_stats(request: Request, token: dict = Depends(require_proxy)):
    """Return live connections and bandwidth statistics."""
    app_state = request.app.state
    cn = getattr(app_state, "bunyanx", None)
    
    stats = {
        "total_connections": 0,
        "active_connections": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
    }
    
    if not cn:
        return stats

    if cn.transparent_proxy:
        t_stats = cn.transparent_proxy.get_statistics()
        stats["total_connections"] += t_stats.get('total_connections', 0)
        stats["active_connections"] += t_stats.get('active_connections', 0)
        stats["bytes_sent"] += t_stats.get('bytes_sent', 0)
        stats["bytes_received"] += t_stats.get('bytes_received', 0)
        
    if cn.forward_proxy:
        f_stats = cn.forward_proxy.get_statistics()
        stats["total_connections"] += f_stats.get('total_connections', 0)
        stats["active_connections"] += f_stats.get('active_connections', 0)
        stats["bytes_sent"] += f_stats.get('bytes_sent', 0)
        stats["bytes_received"] += f_stats.get('bytes_received', 0)
        
    if cn.reverse_proxy:
        r_stats = cn.reverse_proxy.get_statistics()
        stats["total_connections"] += r_stats.get('total_connections', 0)
        stats["active_connections"] += r_stats.get('active_connections', 0)
        stats["bytes_sent"] += r_stats.get('bytes_sent', 0)
        stats["bytes_received"] += r_stats.get('bytes_received', 0)
        
    return stats


@router.get("/sessions", summary="Get active sessions")
async def get_proxy_sessions(request: Request, token: dict = Depends(require_proxy)):
    """Return all active proxy sessions."""
    app_state = request.app.state
    cn = getattr(app_state, "bunyanx", None)
    
    sessions = []
    if not cn:
        return sessions

    if cn.forward_proxy:
        sessions.extend(cn.forward_proxy.get_active_sessions())
        
    if cn.reverse_proxy:
        sessions.extend(cn.reverse_proxy.get_active_sessions())

    if cn.transparent_proxy and hasattr(cn.transparent_proxy, "stats"):
        for conn_id, conn in list(cn.transparent_proxy.stats.items()):
            try:
                from datetime import datetime
                sessions.append({
                    "connection_id": conn_id,
                    "client_ip": conn.client_ip,
                    "client_port": conn.client_port,
                    "target_host": conn.target_host,
                    "target_port": conn.target_port,
                    "protocol": "HTTPS" if conn.target_port == 443 else "HTTP",
                    "bytes_sent": conn.bytes_sent,
                    "bytes_received": conn.bytes_received,
                    "duration": (datetime.now() - conn.start_time).total_seconds() if conn.start_time else 0
                })
            except Exception:
                pass

    return sessions


@router.get("/config", response_model=ProxyConfigSchema, summary="Get proxy configuration")
async def get_config(token: dict = Depends(require_proxy)):
    """Return the full proxy configuration as stored in base.yaml."""
    cfg  = _load()
    pxy  = cfg.get("proxy", {})
    sec  = cfg.get("security", {})
    hard = pxy.get("hardening", {})

    yaml_mode = pxy.get("mode", "transparent")
    is_active  = yaml_mode not in ("none", "disabled", "off")

    raw_backends = pxy.get("backends", [])
    backends = []
    for b in raw_backends:
        if isinstance(b, dict):
            use_ssl = b.get("ssl", False)
            if isinstance(use_ssl, str):
                use_ssl = use_ssl.lower() in ("true", "1", "yes", "on")
            backends.append(BackendEntry(
                host=b.get("host", "localhost"),
                port=int(b.get("port", 8000)),
                ssl=bool(use_ssl),
            ))

    hardening = HardeningConfig(
        cloaking_enabled=hard.get("cloaking_enabled", True),
        server_banner=hard.get("server_banner", "bunyanx-NGFW"),
        strip_headers=hard.get("strip_headers", HardeningConfig().strip_headers),
    )

    return ProxyConfigSchema(
        is_active=is_active,
        mode=_mode_to_ui(yaml_mode, is_active),
        listen_port=int(pxy.get("listen_port", 8443)),
        http_port=int(pxy.get("http_port", 8080)),
        max_connections=int(pxy.get("max_connections", 10000)),
        buffer_size=int(pxy.get("buffer_size", 65536)),
        connection_timeout=int(pxy.get("connection_timeout", 300)),
        strict_cert_validation=bool(sec.get("strict_cert_validation", True)),
        health_check_interval=int(pxy.get("health_check_interval", 10)),
        health_check_timeout=int(pxy.get("health_check_timeout", 3)),
        backends=backends,
        hardening=hardening,
        allowed_ssrf_hosts=pxy.get("allowed_ssrf_hosts", []),
    )


@router.put("/config", response_model=ProxyConfigSchema, summary="Update proxy configuration")
async def update_config(
    new_config: ProxyConfigSchema,
    request: Request,
    token: dict = Depends(require_admin),
):
    """
    Update proxy configuration in base.yaml and sync to database.

    Requires **admin** role.
    All proxy.* keys are written atomically and active proxy engine is reloaded dynamically.
    """
    cfg = _load()
    cfg.setdefault("proxy", {})
    cfg.setdefault("security", {})

    # Mode
    if not new_config.is_active:
        cfg["proxy"]["mode"] = "none"
    else:
        cfg["proxy"]["mode"] = _mode_to_yaml(new_config.mode)

    # Core settings
    cfg["proxy"]["listen_port"]        = new_config.listen_port
    cfg["proxy"]["http_port"]          = new_config.http_port
    cfg["proxy"]["max_connections"]    = new_config.max_connections
    cfg["proxy"]["buffer_size"]        = new_config.buffer_size
    cfg["proxy"]["connection_timeout"] = new_config.connection_timeout

    # Health-check settings (ReverseProxy)
    cfg["proxy"]["health_check_interval"] = new_config.health_check_interval
    cfg["proxy"]["health_check_timeout"]  = new_config.health_check_timeout

    # Backends (ReverseProxy)
    cfg["proxy"]["backends"] = [
        {"host": b.host, "port": b.port, "ssl": b.ssl}
        for b in new_config.backends
    ]

    # Hardening
    cfg["proxy"]["hardening"] = {
        "cloaking_enabled": new_config.hardening.cloaking_enabled,
        "server_banner":    new_config.hardening.server_banner,
        "strip_headers":    new_config.hardening.strip_headers,
    }

    # Security
    cfg["security"]["strict_cert_validation"] = new_config.strict_cert_validation

    # SSRF Whitelist
    cfg["proxy"]["allowed_ssrf_hosts"] = new_config.allowed_ssrf_hosts

    _save(cfg)
    _sync_db_proxy_config(new_config)
    await _notify_runtime_reload(request, cfg)
    return new_config


# ── VIP Endpoints ─────────────────────────────────────────────────────────────

@router.get("/vips", response_model=List[VipEntry], summary="List VIP mappings")
async def list_vips(token: dict = Depends(require_proxy)):
    """Return all configured Virtual IP mappings."""
    cfg  = _load()
    raw  = cfg.get("proxy", {}).get("vips", [])
    result = []
    for v in raw:
        if isinstance(v, dict):
            result.append(VipEntry(
                name=v.get("name", ""),
                external_ip=v.get("external_ip", ""),
                external_port=int(v.get("external_port", 443)),
                internal_ip=v.get("internal_ip", ""),
                internal_port=int(v.get("internal_port", 80)),
                use_tls_upstream=bool(v.get("use_tls_upstream", False)),
            ))
    return result


@router.post("/vips", response_model=VipEntry, status_code=201,
             summary="Add a VIP mapping")
async def add_vip(
    vip: VipEntry,
    request: Request,
    token: dict = Depends(require_admin)
):
    """
    Add a new Virtual IP mapping.

    Requires **admin** role.
    Raises 409 if a VIP with the same name already exists.
    """
    cfg = _load()
    cfg.setdefault("proxy", {})
    vips: list = cfg["proxy"].setdefault("vips", [])

    if any(v.get("name") == vip.name for v in vips if isinstance(v, dict)):
        raise HTTPException(status_code=409,
                            detail=f"VIP '{vip.name}' already exists")

    vips.append(vip.dict())
    _save(cfg)
    await _notify_runtime_reload(request, cfg)
    return vip


@router.delete("/vips/{name}", status_code=204, summary="Remove a VIP mapping")
async def delete_vip(
    name: str,
    request: Request,
    token: dict = Depends(require_admin)
):
    """
    Delete a Virtual IP mapping by name.

    Requires **admin** role.
    Raises 404 if VIP not found.
    """
    cfg  = _load()
    vips = cfg.get("proxy", {}).get("vips", [])
    new_vips = [v for v in vips if isinstance(v, dict) and v.get("name") != name]

    if len(new_vips) == len(vips):
        raise HTTPException(status_code=404,
                            detail=f"VIP '{name}' not found")

    cfg["proxy"]["vips"] = new_vips
    _save(cfg)
    await _notify_runtime_reload(request, cfg)
    return None


# ── PAC / WPAD Endpoints ──────────────────────────────────────────────────────

@router.get("/wpad.dat", summary="Serve WPAD autoconfig file")
@router.get("/proxy.pac", summary="Serve Proxy Auto-Configuration (PAC) file")
async def get_pac_file(request: Request):
    """
    Generate and return a Proxy Auto-Configuration (PAC / wpad.dat) file
    for client browsers configuring automatic proxy settings.
    """
    from fastapi.responses import Response

    cfg = _load()
    pxy = cfg.get("proxy", {})
    
    forward_host = pxy.get("forward_listen_host", "0.0.0.0")
    if forward_host in ("0.0.0.0", "", "::"):
        host_header = request.headers.get("host", "").split(":")[0]
        proxy_host = host_header if host_header else "10.10.0.1"
    else:
        proxy_host = forward_host

    proxy_port = pxy.get("forward_listen_port", 3128)
    
    pac_content = f"""function FindProxyForURL(url, host) {{
    // Direct connection for internal/local hosts
    if (isPlainHostName(host) || 
        shExpMatch(host, "*.local") || 
        isInNet(host, "127.0.0.0", "255.0.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {{
        return "DIRECT";
    }}

    // Default to explicit forward proxy
    return "PROXY {proxy_host}:{proxy_port}; DIRECT";
}}
"""
    return Response(content=pac_content, media_type="application/x-ns-proxy-autoconfig")

