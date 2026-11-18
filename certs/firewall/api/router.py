from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional
from datetime import datetime
import logging
import time
import collections
from api.core.auth import require_admin, make_permission_checker
from sqlalchemy.orm import Session
from system.database.database import get_db
from modules.firewall.models import FirewallRule as DBFirewallRule, ActionEnum

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["firewall"])

# L5: Simple in-memory rate limiter (per admin user, 20 ops/minute)
_block_rate_tracker: dict = collections.defaultdict(list)
_RATE_LIMIT_WINDOW = 60   # seconds
_RATE_LIMIT_MAX    = 20   # max operations per window

def _check_rate_limit(user_id: str):
    now = time.time()
    window = _RATE_LIMIT_WINDOW
    calls = _block_rate_tracker[user_id]
    # Drop calls outside the window
    _block_rate_tracker[user_id] = [t for t in calls if now - t < window]
    if len(_block_rate_tracker[user_id]) >= _RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: max {_RATE_LIMIT_MAX} block/unblock operations per {window}s per user."
        )
    _block_rate_tracker[user_id].append(now)

# ── Singleton UnifiedEvaluator ────────────────────────────────────────────────
# Avoid creating a new evaluator (and re-loading ALL rules from DB) on every
# /policy/evaluate request. Instead we cache one instance per process and
# expose a reload hook that the rule CRUD endpoints call after any write.
_evaluator_cache = None

def _load_firewall_config() -> dict:
    """Retrieve firewall configuration via system ConfigManager, falling back to local settings.yaml."""
    try:
        from system.config.config_manager import ConfigManager
        cfg_mgr = ConfigManager.instance()
        fw_config = cfg_mgr.get("modules.firewall")
        if fw_config and isinstance(fw_config, dict):
            return fw_config
    except Exception as e:
        logger.debug(f"ConfigManager lookup fallback: {e}")

    from pathlib import Path
    import yaml
    config_path = Path("F:/enterprise_ngfw/modules/firewall/config/settings.yaml")
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return data.get("firewall", {})
        except Exception as e:
            logger.error(f"Failed to load firewall config from settings.yaml: {e}")
    return {}

def _get_cached_evaluator(db: Session):
    """Return or create the singleton UnifiedEvaluator for policy evaluation."""
    global _evaluator_cache
    if _evaluator_cache is None:
        from modules.firewall.engine.evaluator import UnifiedEvaluator
        config = _load_firewall_config()
        _evaluator_cache = UnifiedEvaluator(db, config)
        logger.info("UnifiedEvaluator singleton created and cached with config")
    return _evaluator_cache

def _invalidate_evaluator_cache():
    """Call after any rule create / update / delete so the cache is rebuilt."""
    global _evaluator_cache
    _evaluator_cache = None
    logger.info("UnifiedEvaluator cache invalidated — will reload on next request")

# Admins always pass. Non-admins need a DB rule with resource="firewall".
require_firewall = make_permission_checker("firewall")

class FirewallRuleBase(BaseModel):
    name: str = Field(..., description="Rule Name")
    description: Optional[str] = Field(None, description="Description")
    source_ip: str = Field("any", description="Source IP (CIDR notation)")
    destination_ip: str = Field("any", description="Destination IP (CIDR notation)")
    source_port: str = Field("any", description="Source Port(s)")
    destination_port: str = Field("any", description="Destination Port(s)")
    protocol: str = Field("any", pattern="^(tcp|udp|icmp|any|TCP|UDP|ICMP|ANY)$")
    zone_src: str = Field("any", description="Source Zone (e.g. LAN, WAN)")
    zone_dst: str = Field("any", description="Destination Zone (e.g. DMZ, WAN)")
    app_category: str = Field("any", description="Application Category (e.g. Social Media)")
    file_type: str = Field("any", description="File Type Extension (e.g. EXE, PDF)")
    schedule: str = Field("always", description="Schedule Name (e.g. WorkHours)")
    action: ActionEnum = Field(ActionEnum.ALLOW, description="ALLOW, DROP, REJECT, LOG")
    log_traffic: bool = True
    priority: int = Field(100, ge=1, le=1000)
    enabled: bool = True

    @staticmethod
    def _validate_single_ip(ip_str: str) -> None:
        """Validate a single IP or CIDR. Raises ValueError on invalid input."""
        import ipaddress as _ipa
        if '/' in ip_str:
            _ipa.ip_network(ip_str, strict=False)
        else:
            _ipa.ip_address(ip_str)

    @staticmethod
    def _validate_single_port(port_str: str) -> None:
        """Validate a single port or port range. Raises ValueError on invalid input."""
        port_str = port_str.strip()
        if '-' in port_str:
            parts = port_str.split('-', 1)
            start, end = int(parts[0].strip()), int(parts[1].strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Port range out of bounds: {port_str}")
        else:
            val = int(port_str)
            if not 1 <= val <= 65535:
                raise ValueError(f"Port out of range (1-65535): {val}")


    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def validate_ip_field(cls, v: str) -> str:
        """Validate IP addresses and CIDR notation. Accepts 'any' or valid IPv4/IPv6."""
        if not v or v.lower() == 'any':
            return v
        # Support comma-separated IPs/CIDRs
        for ip_str in v.split(','):
            ip_str = ip_str.strip()
            if not ip_str:
                continue
            try:
                cls._validate_single_ip(ip_str)
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"Invalid IP/CIDR '{ip_str}': {e}. "
                    f"Use 'any', a valid IPv4/IPv6 address, or CIDR notation (e.g. 192.168.1.0/24)."
                )
        return v

    @field_validator('source_port', 'destination_port')
    @classmethod
    def validate_port_field(cls, v: str) -> str:
        """Validate port specifications. Accepts 'any', single port, range, or comma-separated."""
        if not v or v.lower() == 'any':
            return v
        for port_str in v.split(','):
            port_str = port_str.strip()
            if not port_str:
                continue
            try:
                cls._validate_single_port(port_str)
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"Invalid port '{port_str}': {e}. "
                    f"Use 'any', a port number (1-65535), or a range (e.g. 1024-65535)."
                )
        return v


class FirewallRuleCreate(FirewallRuleBase):
    pass

class FirewallRuleResponse(FirewallRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PolicyEvaluation(BaseModel):
    action: str
    confidence: float
    reason: str
    matched_rules: List[str]

@router.get("/rules", response_model=List[FirewallRuleResponse])
async def list_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_firewall)):
    """List all firewall rules"""
    rules = db.query(DBFirewallRule).order_by(DBFirewallRule.priority.asc(), DBFirewallRule.id.asc()).offset(skip).limit(limit).all()
    return rules

@router.post("/rules", response_model=FirewallRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: FirewallRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    """Create a new firewall rule"""
    existing = db.query(DBFirewallRule).filter(DBFirewallRule.name == rule.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule name already exists")
    
    db_rule = DBFirewallRule(**rule.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    logger.info(f"Created rule {db_rule.id}: {rule.model_dump()}")
    _invalidate_evaluator_cache()   # force reload on next policy evaluation
    return db_rule

@router.get("/rules/{rule_id}", response_model=FirewallRuleResponse)
async def get_rule(rule_id: int, db: Session = Depends(get_db), token: dict = Depends(require_firewall)):
    db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return db_rule

@router.put("/rules/{rule_id}", response_model=FirewallRuleResponse)
async def update_rule(
    rule_id: int,
    rule: FirewallRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    update_data = rule.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_rule, key, value)
        
    db.commit()
    db.refresh(db_rule)
    logger.info(f"Updated rule {rule_id}: {rule.model_dump()}")
    _invalidate_evaluator_cache()   # force reload on next policy evaluation
    return db_rule

@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    db.delete(db_rule)
    db.commit()
    logger.info(f"Deleted rule {rule_id}")
    _invalidate_evaluator_cache()   # force reload on next policy evaluation
    return {"status": "success", "message": "Rule deleted"}

@router.post("/policy/evaluate", response_model=PolicyEvaluation)
async def evaluate_policy(
    request: Request,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    db: Session = Depends(get_db),
    token: dict = Depends(require_firewall),
):
    """ Evaluate traffic against the current firewall policy (uses cached evaluator) """
    evaluator = _get_cached_evaluator(db)
    context = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 0,
        "dst_port": dst_port,
        "protocol": protocol,
        "interface": "any",
        "app_id": None,
        "domain": None
    }
    result = evaluator.evaluate(context)
    return PolicyEvaluation(
        action=result.get("action", "ALLOW"),
        confidence=result.get("confidence", 1.0),
        reason=result.get("reason", "No specific reason"),
        matched_rules=[result.get("rule_name")] if result.get("rule_name") else []
    )


# ══════════════════════════════════════════════════════════════════════════════
# IP Blocklist Management Endpoints
# Uses IPBlocklistManager from modules.firewall.engine.ip_blocklist
# ══════════════════════════════════════════════════════════════════════════════

class BlockIPRequest(BaseModel):
    reason: str = "Manual block"
    duration_seconds: Optional[int] = None   # None = permanent


@router.get("/block/ips")
async def list_blocked_ips(token: dict = Depends(require_firewall)):
    """List all currently blocked IPs with metadata. Operator+ access."""
    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
    mgr = get_blocklist_manager()
    return {
        "blocked_ips": mgr.get_all(),
        "stats": mgr.get_stats(),
    }


@router.post("/block/{ip_address}", status_code=status.HTTP_200_OK)
async def block_ip(
    request: Request,
    ip_address: str,
    payload: Optional[BlockIPRequest] = Body(default=None),
    token: dict = Depends(require_firewall)
):
    """
    Block an IP at the eBPF kernel level (instant hardware-speed drop).
    Operator+ / Admin access.
    """
    if payload is None:
        payload = BlockIPRequest()
    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
    mgr = get_blocklist_manager()
    try:
        _check_rate_limit(token.get("sub", "unknown"))  # L5: rate limit check
        result = await mgr.block_ip(
            ip=ip_address,
            reason=payload.reason or "Manual block",
            blocked_by=token.get("sub", "admin"),
            duration_seconds=payload.duration_seconds,
        )
        logger.info(f"[API] Blocked {ip_address}: {payload.reason}")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"block_ip error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/block/{ip_address}", status_code=status.HTTP_200_OK)
async def unblock_ip(
    request: Request,
    ip_address: str,
    token: dict = Depends(require_admin)
):
    """
    Unblock a previously blocked IP at the eBPF kernel level.
    Admin only.
    """
    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
    mgr = get_blocklist_manager()
    try:
        _check_rate_limit(token.get("sub", "unknown"))  # L5: rate limit check
        result = await mgr.unblock_ip(ip_address)
        logger.info(f"[API] Unblocked {ip_address}")
        return result
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"unblock_ip error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/block/all", status_code=status.HTTP_200_OK)
async def unblock_all_ips(request: Request, token: dict = Depends(require_admin)):
    """
    Clear the ENTIRE blocklist and unblock all IPs.
    Admin only — use with caution!
    """
    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
    mgr = get_blocklist_manager()
    try:
        result = await mgr.unblock_all()
        logger.warning(f"[API] Entire blocklist cleared by {token.get('sub')}")
        return result
    except Exception as e:
        logger.error(f"unblock_all error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Firewall Policy Optimizer Endpoint
# Uses modules.firewall.engine.db_rule_repository.create_db_optimizer
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/optimizer/suggest", status_code=status.HTTP_200_OK)
async def optimizer_suggest(
    db: Session = Depends(get_db),
    token: dict = Depends(require_firewall),
):
    """
    Run the Smart Firewall Policy Optimizer against the live DB ruleset.

    Returns a list of human-reviewed suggestions:
      - Unused rules (hit_count=0 + not in telemetry for 30 days)
      - Shadowed rules (rule B will never execute because rule A covers it)
      - Mergeable rules (same dest/port/proto/action, differ only in source IP)
      - Reorder recommendations (sort by hit_count descending)

    ⚠️  Advisory only — NO changes are applied automatically.
    """
    try:
        from modules.firewall.engine.db_rule_repository import create_db_optimizer
        from system.database.database import DatabaseManager
        # Reuse the app-level DB manager via g_db singleton if available,
        # otherwise build one from the current session's bind.
        try:
            from system.core.path_manager import resolve_path
            from system.database.database import DatabaseManager as _DBM
            # Attempt to grab the singleton set by the main app
            import system.database.database as _dbmod
            db_manager = getattr(_dbmod, '_app_db_manager', None)
        except Exception:
            db_manager = None

        if db_manager is None:
            # Fallback: wrap the raw session in a minimal duck-type adapter
            class _SessionAdapter:
                def session(self):
                    from contextlib import contextmanager
                    @contextmanager
                    def _ctx():
                        yield db
                    return _ctx()
            db_manager = _SessionAdapter()

        import asyncio
        optimizer = create_db_optimizer(db_manager)
        report = await asyncio.to_thread(optimizer.analyze)
        return report

    except Exception as e:
        logger.error(f"optimizer_suggest error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# XDP / eBPF Acceleration Endpoints
# ══════════════════════════════════════════════════════════════════════════════

class XDPModeRequest(BaseModel):
    mode: str = Field(..., description="Target XDP mode: native | generic | offload | disabled")
    interface: Optional[str] = Field(None, description="Network interface (optional)")


@router.get("/acceleration/xdp/status", status_code=status.HTTP_200_OK)
async def xdp_status(token: dict = Depends(require_firewall)):
    """
    Return current XDP / eBPF engine status and statistics.
    """
    try:
        from modules.firewall.engine.ip_blocklist import get_blocklist_manager
        mgr = get_blocklist_manager()
        stats = mgr.get_stats()

        # Try to get live XDP stats from the engine
        xdp_stats = {}
        try:
            from system.core.acceleration_bridge import AccelerationBridge
            # AccelerationBridge stores the XDP engine at _xdp
            # We access it via the module singleton approach
            import system.core.acceleration_bridge as _ab_mod
            bridge = getattr(_ab_mod, '_singleton_bridge', None)
            if bridge and bridge._xdp:
                xdp_stats = bridge._xdp.get_statistics()
        except Exception:
            pass

        return {
            "ebpf_active": stats.get("ebpf_active", False),
            "blocked_ips_count": stats.get("total_blocked", 0),
            "xdp_stats": xdp_stats,
        }
    except Exception as e:
        logger.error(f"xdp_status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/acceleration/xdp/mode", status_code=status.HTTP_200_OK)
async def switch_xdp_mode(
    payload: XDPModeRequest,
    token: dict = Depends(require_admin),
):
    """
    Switch XDP attachment mode at runtime without service restart.
    Admin only.

    Valid modes: native | generic | offload | disabled
    """
    try:
        from acceleration.ebpf.xdp_mode_switcher import XDPModeSwitcher, XDPMode

        valid_modes = {m.value for m in XDPMode}
        if payload.mode not in valid_modes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid mode '{payload.mode}'. Valid: {sorted(valid_modes)}"
            )

        target = XDPMode(payload.mode)

        # Retrieve the live XDP engine from the main application
        try:
            from system.core.engine import BunyanXApplication
            import system.core.engine as _eng_mod
            app_instance = getattr(_eng_mod, '_app_singleton', None)
            xdp_engine = getattr(app_instance, 'xdp_engine', None) if app_instance else None
        except Exception:
            xdp_engine = None

        if xdp_engine is None:
            raise HTTPException(status_code=503, detail="XDP engine not available")

        switcher = XDPModeSwitcher(xdp_engine)
        success = await switcher.switch_mode(target, payload.interface)

        if not success:
            raise HTTPException(status_code=500, detail=f"Failed to switch to mode '{payload.mode}'")

        logger.info(f"[API] XDP mode switched to '{payload.mode}' by {token.get('sub')}")
        return {
            "status": "ok",
            "mode": payload.mode,
            "interface": payload.interface or getattr(xdp_engine, 'interface', 'unknown'),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"switch_xdp_mode error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ══════════════════════════════════════════════════════════════════════════════
# NGFW Real-Time Observability
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/stats", status_code=status.HTTP_200_OK)
async def firewall_plugin_stats(token: dict = Depends(require_firewall)):
    """
    Returns live performance telemetry of the Firewall:
    - Active TCP State Tracker Count
    - Circuit Breaker Health
    """
    try:
        import system.core.engine as _eng_mod
        app_instance = getattr(_eng_mod, '_app_instance', None) or getattr(_eng_mod, '_app_singleton', None)
        
        if not app_instance:
            # Fallback mock if running in isolated API mode
            return {"status": "running", "active_connections": 0, "circuit_breaker": "unknown"}
            
        # Extract the firewall plugin from the module manager or registry pipeline
        fw_plugin = None
        if hasattr(app_instance, 'module_registry') and app_instance.module_registry:
            fw_module = app_instance.module_registry.get_module("firewall")
            if fw_module:
                fw_plugin = getattr(fw_module, 'instance', fw_module)
        if not fw_plugin and hasattr(app_instance, 'module_manager') and app_instance.module_manager:
            fw_plugin = app_instance.module_manager.get_plugin("firewall")

        if fw_plugin and hasattr(fw_plugin, 'get_stats'):
            return fw_plugin.get_stats()
            
        return {"status": "running", "active_connections": 0, "circuit_breaker": "healthy"}
    except Exception as e:
        logger.error(f"Firewall stats error: {e}", exc_info=True)
        return {"status": "running", "active_connections": 0, "circuit_breaker": "degraded", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# Administrative Config Management
# ══════════════════════════════════════════════════════════════════════════════

class GeoIPConfigSchema(BaseModel):
    db_path: str = "system/data/GeoIP2-City.mmdb"
    asn_db_path: str = "system/data/GeoLite2-ASN.mmdb"
    blocked_countries: List[str] = Field(default_factory=list)
    whitelisted_countries: List[str] = Field(default_factory=list)

class CustomPortSchema(BaseModel):
    name: str = Field(..., description="Port alias or description (e.g. DNS Security)")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field("tcp", description="Protocol: tcp, udp, or both")
    direction: str = Field("input", description="Direction: input, forward, or both")
    enabled: bool = Field(True, description="Enable or disable this port")

class FirewallConfigSchema(BaseModel):
    enabled: bool = True
    mode: str = "enforce"
    default_policy: str = "DROP"
    state_timeout_seconds: int = 300
    max_active_connections: int = 100000
    geoip: GeoIPConfigSchema = Field(default_factory=GeoIPConfigSchema)
    zones: dict = Field(default_factory=dict)
    # Port allowlists (configurable from UI)
    management_ports: List[int] = Field(
        default_factory=lambda: [22, 443, 8888],
        description="Always-allowed ports (SSH, HTTPS, Management API)"
    )
    dev_ports_enabled: bool = Field(
        True,
        description="Enable dev/proxy bypass ports (disable in production)"
    )
    dev_ports: List[int] = Field(
        default_factory=lambda: [8000, 5173],
        description="Dev/proxy bypass ports (Vite, bunyanx proxy)"
    )
    custom_ports: List[CustomPortSchema] = Field(
        default_factory=list,
        description="Unlimited dynamic custom ports for other modules"
    )

@router.get("/config", response_model=FirewallConfigSchema)
async def get_firewall_config(token: dict = Depends(require_firewall)):
    """Retrieve the current firewall configuration settings from settings.yaml."""
    cfg = _load_firewall_config()
    return FirewallConfigSchema(
        enabled=cfg.get("enabled", True),
        mode=cfg.get("mode", "enforce"),
        default_policy=cfg.get("default_policy", "DROP"),
        state_timeout_seconds=cfg.get("state_timeout_seconds", 300),
        max_active_connections=cfg.get("max_active_connections", 100000),
        geoip=GeoIPConfigSchema(
            db_path=cfg.get("geoip", {}).get("db_path", "system/data/GeoIP2-City.mmdb"),
            asn_db_path=cfg.get("geoip", {}).get("asn_db_path", "system/data/GeoLite2-ASN.mmdb"),
            blocked_countries=cfg.get("geoip", {}).get("blocked_countries", []),
            whitelisted_countries=cfg.get("geoip", {}).get("whitelisted_countries", []),
        ),
        zones=cfg.get("zones", {}),
        management_ports=cfg.get("management_ports", [22, 443, 8888]),
        dev_ports_enabled=cfg.get("dev_ports_enabled", True),
        dev_ports=cfg.get("dev_ports", [8000, 5173]),
        custom_ports=[
            CustomPortSchema(
                name=cp.get("name", "Unknown"),
                port=cp.get("port", 0),
                protocol=cp.get("protocol", "tcp"),
                direction=cp.get("direction", "input"),
                enabled=cp.get("enabled", True),
            )
            for cp in cfg.get("custom_ports", [])
        ],
    )

@router.put("/config", status_code=status.HTTP_200_OK)
async def update_firewall_config(
    payload: FirewallConfigSchema,
    token: dict = Depends(require_admin)
):
    """
    Update firewall config settings in settings.yaml.
    Validates updated values and reloads the engine.
    """
    from pathlib import Path
    import yaml
    from modules.firewall.config.validator import validate_firewall_config

    raw_config_to_save = {
        "firewall": {
            "enabled": payload.enabled,
            "mode": payload.mode,
            "default_policy": payload.default_policy,
            "state_timeout_seconds": payload.state_timeout_seconds,
            "max_active_connections": payload.max_active_connections,
            "geoip": {
                "db_path": payload.geoip.db_path,
                "asn_db_path": payload.geoip.asn_db_path,
                "blocked_countries": payload.geoip.blocked_countries,
                "whitelisted_countries": payload.geoip.whitelisted_countries,
            },
            "zones": payload.zones,
            "management_ports": payload.management_ports,
            "dev_ports_enabled": payload.dev_ports_enabled,
            "dev_ports": payload.dev_ports,
            "custom_ports": [
                {
                    "name": cp.name,
                    "port": cp.port,
                    "protocol": cp.protocol.lower(),
                    "direction": cp.direction.lower(),
                    "enabled": cp.enabled
                } for cp in payload.custom_ports
            ]
        }
    }

    try:
        validate_firewall_config(raw_config_to_save)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Configuration validation failed: {val_err}"
        )

    config_path = Path("F:/enterprise_ngfw/modules/firewall/config/settings.yaml")
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw_config_to_save, f, default_flow_style=False, allow_unicode=True)
    except Exception as save_err:
        logger.error(f"Failed to write firewall config to settings.yaml: {save_err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to write settings to disk: {save_err}"
        )

    _invalidate_evaluator_cache()

    try:
        from system.config.config_manager import ConfigManager
        ConfigManager.instance().force_reload()
        logger.info("ConfigManager force-reloaded post firewall settings update")
    except Exception as cfg_err:
        logger.debug(f"ConfigManager reload notification error: {cfg_err}")

    try:
        from system.core.engine import BunyanXApplication
        import system.core.engine as _eng_mod
        app_instance = getattr(_eng_mod, '_app_singleton', None)
        if app_instance:
            fw_plugin = app_instance.module_manager.get_plugin("firewall")
            if fw_plugin:
                fw_plugin.config = raw_config_to_save
                if hasattr(fw_plugin, 'reload_rules'):
                    fw_plugin.reload_rules()
                logger.info("FirewallPlugin config hot-reloaded dynamically")
    except Exception as reload_err:
        logger.warning(f"Failed to reload running firewall plugin instance: {reload_err}")

    return {"status": "success", "message": "Firewall configuration updated and hot-reloaded successfully."}


# ══════════════════════════════════════════════════════════════════════════════
#  IP Whitelist API — Auto-Block Exemptions
#  ─────────────────────────────────────────────────────────────────────────────
#  Manages the YAML-backed whitelist of IPs/CIDRs that are exempt from
#  automatic blocking by inspection_bridge and xdp_engine.
#
#  The whitelist is stored in:
#    modules/firewall/config/ip_whitelist.yaml
#
#  Changes are written to disk immediately and survive restarts.
# ══════════════════════════════════════════════════════════════════════════════

class _WhitelistNetworkIn(BaseModel):
    """Request body for adding a CIDR network to the whitelist."""
    cidr:  str = Field(..., examples=["10.10.0.0/24"], description="CIDR range, e.g. 10.10.0.0/24")
    label: str = Field("", description="Human-readable name for this entry")
    reason: str = Field("", description="Why this network is whitelisted")

class _WhitelistHostIn(BaseModel):
    """Request body for adding a single IP host to the whitelist."""
    ip:    str = Field(..., examples=["203.0.113.42"], description="Single IPv4 or IPv6 address")
    label: str = Field("", description="Human-readable name for this entry")
    reason: str = Field("", description="Why this IP is whitelisted")

class _WhitelistNetworkDeleteIn(BaseModel):
    """Request body for removing a CIDR network from the whitelist."""
    cidr: str = Field(..., examples=["10.10.0.0/24"], description="CIDR to remove")


def _wl():
    """Shorthand — return the singleton IPWhitelistManager."""
    from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager
    return get_whitelist_manager()


@router.get(
    "/firewall/whitelist",
    summary="List all whitelist entries",
    description="Returns all CIDR networks and single-host IPs currently in the auto-block exemption list.",
)
async def whitelist_list(admin=Depends(require_admin)):
    """Return the full whitelist (networks + hosts)."""
    return _wl().list_all()


@router.post(
    "/firewall/whitelist/networks",
    status_code=status.HTTP_201_CREATED,
    summary="Add a CIDR network to the whitelist",
    description="Adds a CIDR range (e.g. 10.10.0.0/24) to the auto-block exemption list. Persisted to YAML immediately.",
)
async def whitelist_add_network(body: _WhitelistNetworkIn, admin=Depends(require_admin)):
    """Add a CIDR network to the persistent whitelist."""
    try:
        added_by = getattr(admin, "username", None) or getattr(admin, "sub", "api")
        meta = _wl().add_network(
            cidr=body.cidr,
            label=body.label,
            reason=body.reason,
            added_by=str(added_by),
        )
        logger.info("Whitelist network added: %s by %s", body.cidr, added_by)
        return {"status": "added", "entry": meta}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Whitelist add_network error: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.delete(
    "/firewall/whitelist/networks",
    summary="Remove a CIDR network from the whitelist",
    description="Removes a CIDR range from the auto-block exemption list. Persisted to YAML immediately.",
)
async def whitelist_remove_network(body: _WhitelistNetworkDeleteIn, admin=Depends(require_admin)):
    """Remove a CIDR network from the persistent whitelist."""
    try:
        removed = _wl().remove_network(cidr=body.cidr)
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Network '{body.cidr}' not found in whitelist.",
            )
        added_by = getattr(admin, "username", None) or getattr(admin, "sub", "api")
        logger.info("Whitelist network removed: %s by %s", body.cidr, added_by)
        return {"status": "removed", "cidr": body.cidr}
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Whitelist remove_network error: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/firewall/whitelist/hosts",
    status_code=status.HTTP_201_CREATED,
    summary="Add a single IP to the whitelist",
    description="Adds a single IPv4/IPv6 address to the auto-block exemption list. Persisted to YAML immediately.",
)
async def whitelist_add_host(body: _WhitelistHostIn, admin=Depends(require_admin)):
    """Add a single IP host to the persistent whitelist."""
    try:
        added_by = getattr(admin, "username", None) or getattr(admin, "sub", "api")
        meta = _wl().add_host(
            ip=body.ip,
            label=body.label,
            reason=body.reason,
            added_by=str(added_by),
        )
        logger.info("Whitelist host added: %s by %s", body.ip, added_by)
        return {"status": "added", "entry": meta}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Whitelist add_host error: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.delete(
    "/firewall/whitelist/hosts/{ip}",
    summary="Remove a single IP from the whitelist",
    description="Removes a single IP from the auto-block exemption list. Persisted to YAML immediately.",
)
async def whitelist_remove_host(ip: str, admin=Depends(require_admin)):
    """Remove a single IP host from the persistent whitelist."""
    try:
        removed = _wl().remove_host(ip=ip)
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host '{ip}' not found in whitelist.",
            )
        added_by = getattr(admin, "username", None) or getattr(admin, "sub", "api")
        logger.info("Whitelist host removed: %s by %s", ip, added_by)
        return {"status": "removed", "ip": ip}
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Whitelist remove_host error: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/firewall/whitelist/reload",
    summary="Reload whitelist from YAML file",
    description="Re-reads ip_whitelist.yaml from disk without restarting the process. Use after manual file edits.",
)
async def whitelist_reload(admin=Depends(require_admin)):
    """Reload the whitelist from ip_whitelist.yaml without a process restart."""
    try:
        summary = _wl().reload()
        added_by = getattr(admin, "username", None) or getattr(admin, "sub", "api")
        logger.info("Whitelist reloaded by %s: %s", added_by, summary)
        return {"status": "reloaded", "loaded": summary}
    except Exception as exc:
        logger.error("Whitelist reload error: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
